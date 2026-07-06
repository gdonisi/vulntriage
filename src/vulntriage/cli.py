"""CLI entry point: orchestrates the full triage pipeline.

Run the v2 triage pipeline on one or more scanner output files:

    uv run python main.py --input data/synthetic_findings.json \
        --provider lmstudio --model qwen3.5-4b \
        --asset-registry data/assets.yaml \
        --remediate --output-format both

Merge findings from multiple scanner outputs at once:

    uv run python main.py --input data/sample_nmap.xml data/sample_nuclei.jsonl \
        --provider lmstudio --model qwen3.5-4b --remediate

Run the dockerized Nuclei scanner, then continue straight into triage
(--scan-only would stop after the scan):

    uv run python main.py --scan nuclei --target 192.168.1.5 \
        --provider lmstudio --model qwen3.5-4b

Only run the Nuclei scan, save output and exit:

    uv run python main.py --scan nuclei --target 192.168.1.5 --scan-only

Use a custom OpenAI-compatible provider (local or cloud):

    uv run python main.py --input data/synthetic_findings.json \
        --provider custom --base-url http://localhost:8080/v1 --model my-model

    uv run python main.py --input data/synthetic_findings.json \
        --provider custom --base-url https://api.example.com/v1 \
        --api-key sk-... --model gpt-4o

Block cloud providers (only self-hosted backends allowed):

    uv run python main.py --input data/synthetic_findings.json \
        --provider lmstudio --model qwen3.5-4b --local-only

    uv run python main.py --input data/synthetic_findings.json \
        --provider custom --base-url http://localhost:8080/v1 \
        --model my-model --local --local-only

Run the evaluation experiment grid (single model):

    uv run python main.py --evaluate --input data/synthetic_findings.json \
        --provider lmstudio --model qwen3.5-4b

Run the evaluation experiment grid from a config file (multiple models):

    uv run python main.py --evaluate --eval-config data/eval_config.json

Start the local web interface (see docs/specs/webapp-design.md):

    uv run uvicorn vulntriage.webapp.app:app --reload
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from .evaluation import (
    ExperimentConfig,
    ModelSpec,
    load_config,
    run_experiment,
)
from .llm import LOCAL_PROVIDERS, is_local_provider, make_client
from .parser import parse
from .pipeline import run_pipeline
from .scanner import run_nuclei

# Sentinel for ``--save-intermediates`` with no explicit path: intermediates
# are written under ``<run_dir>/intermediates/``.
_DEFAULT_INTERMEDIATES = "__default__"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulntriage",
        description="LLM-enabled vulnerability triage pipeline",
    )
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument(
        "--input",
        nargs="+",
        help="One or more scanner output files (xml/jsonl/json); findings are merged",
    )
    src.add_argument(
        "--scan",
        choices=["nuclei"],
        help="Run a dockerized scanner against --target, then continue to triage "
        "(unless --scan-only is set)",
    )
    p.add_argument("--evaluate", action="store_true", help="Run the evaluation experiment grid")
    p.add_argument("--eval-config", help="JSON experiment config for --evaluate (multi-model grid)")
    p.add_argument("--target", help="Target for --scan")
    p.add_argument(
        "--provider",
        choices=[
            "custom",
            "lmstudio",
            "ollama",
            "llamacpp",
            "vllm",
            "openai",
            "openrouter",
            "anthropic",
            "google",
            "deepseek",
        ],
        help="LLM provider (required unless --scan-only / --evaluate --eval-config is set)",
    )
    p.add_argument(
        "--base-url",
        default=None,
        help="Base URL for the OpenAI-compatible endpoint (required when --provider custom)",
    )
    p.add_argument(
        "--api-key",
        default=None,
        help="API key for the custom provider (optional; omit for keyless local servers)",
    )
    p.add_argument(
        "--local",
        action="store_true",
        help="Mark a custom provider as self-hosted (for --local-only gating). "
        "Only meaningful with --provider custom.",
    )
    p.add_argument(
        "--model",
        help=(
            "Model name for the chosen provider "
            "(required unless --scan-only / --evaluate --eval-config is set). "
            "For --provider custom, use any model name your endpoint recognises."
        ),
    )
    p.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high"],
        default=None,
        help=(
            "Thinking/reasoning effort for models that support it "
            "(provider support varies). Omit for standard (non-reasoning) behaviour."
        ),
    )
    p.add_argument(
        "--local-only",
        action="store_true",
        help=f"Block cloud providers; only local backends are allowed "
        f"({', '.join(sorted(LOCAL_PROVIDERS))}).",
    )
    p.add_argument("--asset-registry", default=None, help="YAML mapping host->criticality")
    p.add_argument(
        "--output",
        default=None,
        help=(
            "Output location. For HTML/PDF/both and --evaluate: a directory "
            "(default: a timestamped dir under output/runs or output/eval, so "
            "previous runs are never overwritten). For text: path to a file "
            "(default: stdout)."
        ),
    )
    p.add_argument(
        "--output-format",
        choices=["text", "html", "pdf", "both"],
        default="text",
        help="Report format. 'text' keeps the v1 plain-text report.",
    )
    p.add_argument(
        "--save-intermediates",
        nargs="?",
        const=_DEFAULT_INTERMEDIATES,
        default=None,
        help="Dump enriched/scored/prioritized/remediated JSON for evaluation. "
        "With no value, writes to <run_dir>/intermediates/.",
    )
    p.add_argument(
        "--scan-only",
        action="store_true",
        help="Only run the scanner and save output; skip the triage pipeline. Use with --scan.",
    )
    # v2 flags
    p.add_argument(
        "--remediate",
        action="store_true",
        help="Run the Remediation Recommendation Generator after prioritization",
    )
    p.add_argument(
        "--rag",
        dest="rag",
        action="store_true",
        default=True,
        help="Use the light RAG knowledge base for remediation (default).",
    )
    p.add_argument(
        "--no-rag",
        dest="rag",
        action="store_false",
        help="Disable RAG; remediation uses LLM knowledge only.",
    )
    p.add_argument(
        "--kb",
        default="data/cve_kb.json",
        help="Path to the remediation RAG knowledge base (default: data/cve_kb.json)",
    )
    p.add_argument(
        "--prompt-strategy",
        choices=["few-shot", "zero-shot"],
        default="few-shot",
        help="Exploitability scorer prompting strategy (default: few-shot, the v1 behaviour)",
    )
    p.add_argument(
        "--ensemble",
        help=(
            "Comma-separated extra scoring models for a multi-LLM ensemble, each "
            "as 'provider:model' (split on the first colon). Only the exploitability "
            "scorer fans out; --provider/--model is the primary (used for enrichment + "
            "remediation and is the first ensemble member). Example: "
            "'ollama:llama3.1,openai:gpt-4o-mini'."
        ),
    )
    p.add_argument(
        "--quorum",
        type=int,
        default=None,
        help=(
            "Strict-majority quorum for ensemble scoring (default: floor(N/2)+1). "
            "A label is accepted only if >= quorum models agree; otherwise the finding "
            "is flagged Unresolved."
        ),
    )
    p.add_argument(
        "--web",
        action="store_true",
        help="Start the local web interface (alias for: uv run uvicorn vulntriage.webapp.app:app)",
    )
    p.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="Repetitions per condition in --evaluate mode (default: 3)",
    )
    return p


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _check_local_only(
    provider: str | None,
    models: list[ModelSpec] | None = None,
    ensemble: list[tuple[str, str]] | None = None,
    custom_is_local: bool = False,
) -> str | None:
    """Validate the --local-only constraint. Returns an error message or None."""
    offenders: list[str] = []
    # For custom providers the local flag is set explicitly; for built-in
    # providers we check against the hardcoded set.
    if provider is not None:
        if provider == "custom":
            if not custom_is_local:
                offenders.append("custom")
        elif not is_local_provider(provider):
            offenders.append(f"{provider}")
    if models:
        for m in models:
            if not is_local_provider(m.provider):
                offenders.append(f"{m.provider}/{m.model}")
    if ensemble:
        for prov, mdl in ensemble:
            if not is_local_provider(prov):
                offenders.append(f"{prov}:{mdl}")
    if offenders:
        return (
            "--local-only is set but cloud provider(s) requested: "
            + ", ".join(sorted(set(offenders)))
            + f". Allowed local providers: {', '.join(sorted(LOCAL_PROVIDERS))}"
            + " (or use --provider custom --local)."
        )
    return None


def _parse_ensemble(spec: str) -> list[tuple[str, str]]:
    """Parse '--ensemble a:b,c:d' into [(a, b), (c, d)] (first-colon split)."""
    out: list[tuple[str, str]] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" not in chunk:
            raise ValueError(f"Invalid --ensemble member {chunk!r}: expected 'provider:model'")
        prov, mdl = chunk.split(":", 1)
        prov, mdl = prov.strip(), mdl.strip()
        if not prov or not mdl:
            raise ValueError(f"Invalid --ensemble member {chunk!r}: empty provider or model")
        out.append((prov, mdl))
    return out


def _validate_custom_args(args: argparse.Namespace) -> str | None:
    """Validate custom-provider-related CLI args. Returns an error or None."""
    is_custom = args.provider == "custom" if args.provider else False
    if args.base_url and not is_custom:
        return "--base-url is only meaningful with --provider custom"
    if args.api_key and not is_custom:
        return "--api-key is only meaningful with --provider custom"
    if args.local and not is_custom:
        return "--local is only meaningful with --provider custom"
    if is_custom and not args.base_url:
        return "--base-url is required when --provider custom"
    return None


def _run_evaluate(args: argparse.Namespace) -> int:
    """Run the evaluation experiment grid."""
    ts = _timestamp()

    # Custom provider validation for --evaluate (single-model path only).
    if not args.eval_config:
        err = _validate_custom_args(args)
        if err:
            print(err, file=sys.stderr)
            return 2

    if args.eval_config:
        config = load_config(args.eval_config)
        # Fall back to a timestamped dir if the config doesn't specify one.
        if not config.output_dir:
            config.output_dir = f"output/eval/{ts}"
    else:
        if not args.provider or not args.model:
            print(
                "--evaluate needs either --eval-config or --provider/--model",
                file=sys.stderr,
            )
            return 2
        if not args.input:
            print("--evaluate (without --eval-config) needs --input", file=sys.stderr)
            return 2
        if len(args.input) > 1:
            print(
                "--evaluate uses a single --input dataset (with ground truth); "
                "multiple inputs are not supported in eval mode.",
                file=sys.stderr,
            )
            return 2
        config = ExperimentConfig(
            input_path=args.input[0],
            asset_registry=args.asset_registry,
            kb_path=args.kb,
            models=[ModelSpec(args.provider, args.model)],
            prompt_strategies=["few-shot", "zero-shot"],
            rag_conditions=[True, False],
            repeats=args.repeats,
            output_dir=args.output or f"output/eval/{ts}",
        )

    if args.local_only:
        err = _check_local_only(None, config.models)
        if err:
            print(err, file=sys.stderr)
            return 2

    run_experiment(config)
    return 0


def _run_web(args: argparse.Namespace) -> int:
    """Start the uvicorn server for the webapp."""
    import uvicorn

    uvicorn.run(
        "vulntriage.webapp.app:app",
        host="0.0.0.0",
        port=9000,
        reload=False,
        log_level="info",
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.web:
        return _run_web(args)

    if args.evaluate:
        return _run_evaluate(args)

    if not args.input and not args.scan:
        print("One of --input or --scan is required (or use --evaluate / --web)", file=sys.stderr)
        return 2

    # --provider and --model are optional when scanning only.
    if not args.scan_only and (not args.provider or not args.model):
        print("--provider and --model are required for the triage pipeline", file=sys.stderr)
        return 2

    # Ensemble is a triage-run feature; parse + validate it here.
    ensemble_members: list[tuple[str, str]] = []
    if args.ensemble:
        if args.scan_only:
            print("--ensemble cannot be combined with --scan-only", file=sys.stderr)
            return 2
        try:
            ensemble_members = _parse_ensemble(args.ensemble)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
        if not ensemble_members:
            print("--ensemble needs at least one provider:model member", file=sys.stderr)
            return 2

    # Validate custom-provider args early before any work.
    if not args.scan_only and not args.evaluate:
        err = _validate_custom_args(args)
        if err:
            print(err, file=sys.stderr)
            return 2

    # --local-only gates cloud providers for the triage pipeline (including
    # every ensemble member).
    if not args.scan_only and args.local_only:
        err = _check_local_only(
            args.provider,
            ensemble=ensemble_members or None,
            custom_is_local=bool(args.local),
        )
        if err:
            print(err, file=sys.stderr)
            return 2

    # 1. Acquire scanner results.
    if args.scan == "nuclei":
        if not args.target:
            print("--scan requires --target", file=sys.stderr)
            return 2
        out_path = Path(f"data/nuclei_scan_{int(time.time())}.jsonl")
        run_nuclei(args.target, out_path)
        print(f"[pipeline] nuclei scan output saved to {out_path.resolve()}")
        if args.scan_only:
            return 0
        input_paths = [str(out_path)]
    else:
        if args.scan_only:
            print("--scan-only requires --scan nuclei", file=sys.stderr)
            return 2
        input_paths = list(args.input)

    # 2. Parse (and merge) findings from all inputs.
    findings: list = []
    for ip in input_paths:
        parsed = parse(ip)
        findings.extend(parsed)
        print(f"[pipeline] parsed {len(parsed)} findings from {ip}")
    if not findings:
        print("[pipeline] no findings to process")
        return 0

    # 3. Build LLM client(s).
    client = make_client(
        args.provider,
        args.model,
        reasoning_effort=args.reasoning_effort,
        base_url=args.base_url,
        api_key=args.api_key,
        local=args.local,
    )
    # Ensemble scoring clients: the primary is first, then the extras.
    scoring_clients = None
    if ensemble_members:
        extras = [
            make_client(prov, mdl, reasoning_effort=args.reasoning_effort)
            for prov, mdl in ensemble_members
        ]
        scoring_clients = [client, *extras]
        print(
            f"[pipeline] ensemble of {len(scoring_clients)} scoring model(s) "
            f"(quorum={args.quorum or (len(scoring_clients) // 2 + 1)})"
        )

    # Compute the run id once so the report dir and the intermediates dir share it.
    ts = _timestamp()
    if args.output and args.output_format in ("html", "pdf", "both"):
        run_dir = Path(args.output)
    elif args.output:
        run_dir = Path(args.output).parent
    else:
        run_dir = Path("output/runs") / ts

    save_inter = args.save_intermediates is not None
    # An explicit --save-intermediates <dir> writes there directly (preserving
    # the v2 behaviour); with no value, run_pipeline defaults to <run_dir>/intermediates/.
    explicit_inter = (
        args.save_intermediates
        if args.save_intermediates and args.save_intermediates != _DEFAULT_INTERMEDIATES
        else None
    )
    result = run_pipeline(
        findings,
        client,
        out_dir=run_dir,
        output_format=args.output_format,
        remediate=args.remediate,
        use_rag=args.rag,
        kb_path=args.kb,
        prompt_strategy=args.prompt_strategy,
        asset_registry=args.asset_registry,
        save_intermediates_flag=save_inter,
        intermediates_dir=explicit_inter,
        text_output=args.output if args.output_format == "text" else None,
        scoring_clients=scoring_clients,
        scoring_quorum=args.quorum,
    )
    if result.text_report is not None:
        print(result.text_report)
    return 0
