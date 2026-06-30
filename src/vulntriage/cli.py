"""CLI entry point: orchestrates the full triage pipeline.

Run the v1/v2 triage pipeline on a scanner output file:

    uv run python main.py --input data/synthetic_findings.json \
        --provider lmstudio --model qwen3.5-4b \
        --asset-registry data/assets.yaml \
        --remediate --output-format both

Run the dockerized Nuclei scanner first, then triage:

    uv run python main.py --scan nuclei --target 192.168.1.5 \
        --provider lmstudio --model qwen3.5-4b

Only run the Nuclei scan, save output and exit:

    uv run python main.py --scan nuclei --target 192.168.1.5 --scan-only

Run the evaluation experiment grid (single model):

    uv run python main.py --evaluate --input data/synthetic_findings.json \
        --provider lmstudio --model qwen3.5-4b

Run the evaluation experiment grid from a config file (multiple models):

    uv run python main.py --evaluate --eval-config data/eval_config.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .enricher import enrich_all
from .evaluation import (
    ExperimentConfig,
    ModelSpec,
    load_config,
    run_experiment,
)
from .llm import make_client
from .parser import parse
from .prioritizer import load_asset_registry, prioritize
from .remediator import remediate_all
from .report_composer import compose as compose_report
from .reporter import render
from .scanner import run_nuclei
from .scorer import score_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulntriage",
        description="LLM-enabled vulnerability triage pipeline",
    )
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("--input", help="Path to scanner output (xml/jsonl/json)")
    src.add_argument(
        "--scan",
        choices=["nuclei"],
        help="Run a dockerized scanner against --target",
    )
    p.add_argument("--evaluate", action="store_true", help="Run the evaluation experiment grid")
    p.add_argument("--eval-config", help="JSON experiment config for --evaluate (multi-model grid)")
    p.add_argument("--target", help="Target for --scan")
    p.add_argument(
        "--provider",
        choices=[
            "lmstudio",
            "ollama",
            "llamacpp",
            "vllm",
            "openai",
            "openrouter",
        ],
        help="LLM provider (required unless --scan-only / --evaluate --eval-config is set)",
    )
    p.add_argument(
        "--model",
        help=(
            "Model name for the chosen provider "
            "(required unless --scan-only / --evaluate --eval-config is set)"
        ),
    )
    p.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high"],
        default=None,
        help=(
            "Thinking effort for OpenAI reasoning models. "
            "Omit for standard (non-reasoning) behaviour."
        ),
    )
    p.add_argument("--asset-registry", default=None, help="YAML mapping host->criticality")
    p.add_argument(
        "--output",
        default=None,
        help="Write report to this path (default: stdout). For HTML/PDF a directory is expected.",
    )
    p.add_argument(
        "--output-format",
        choices=["text", "html", "pdf", "both"],
        default="text",
        help="Report format. 'text' keeps the v1 plain-text report.",
    )
    p.add_argument(
        "--save-intermediates",
        default=None,
        help="Directory to dump enriched/scored/prioritized/remediated JSON for evaluation",
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
        "--repeats",
        type=int,
        default=3,
        help="Repetitions per condition in --evaluate mode (default: 3)",
    )
    return p


def _run_evaluate(args: argparse.Namespace) -> int:
    """Run the evaluation experiment grid."""
    if args.eval_config:
        config = load_config(args.eval_config)
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
        config = ExperimentConfig(
            input_path=args.input,
            asset_registry=args.asset_registry,
            kb_path=args.kb,
            models=[ModelSpec(args.provider, args.model)],
            prompt_strategies=["few-shot", "zero-shot"],
            rag_conditions=[True, False],
            repeats=args.repeats,
        )
    run_experiment(config)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.evaluate:
        return _run_evaluate(args)

    if not args.input and not args.scan:
        print("One of --input or --scan is required (or use --evaluate)", file=sys.stderr)
        return 2

    # --provider and --model are optional when scanning only.
    if not args.scan_only and (not args.provider or not args.model):
        print("--provider and --model are required for the triage pipeline", file=sys.stderr)
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
        input_path = str(out_path)
    else:
        if args.scan_only:
            print("--scan-only requires --scan nuclei", file=sys.stderr)
            return 2
        input_path = args.input

    findings = parse(input_path)
    print(f"[pipeline] parsed {len(findings)} findings from {input_path}")
    if not findings:
        print("[pipeline] no findings to process")
        return 0

    # 2. Build LLM client.
    client = make_client(
        args.provider,
        args.model,
        reasoning_effort=args.reasoning_effort,
    )

    few_shot = args.prompt_strategy == "few-shot"

    # 3. Enrich.
    print("[pipeline] enriching findings...")
    enriched = enrich_all(findings, client)

    # 4. Score exploitability.
    print(f"[pipeline] scoring exploitability (prompt strategy: {args.prompt_strategy})...")
    scored = score_all(enriched, client, few_shot=few_shot)

    # 5. Prioritize.
    print("[pipeline] prioritizing...")
    assets = load_asset_registry(args.asset_registry)
    prioritized = prioritize(scored, assets)

    # 6. Remediate (optional, v2).
    remediated = None
    if args.remediate:
        rag_label = "on" if args.rag else "off"
        print(f"[pipeline] generating remediation (RAG: {rag_label})...")
        remediated = remediate_all(prioritized, client, kb_path=args.kb, use_rag=args.rag)

    # 7. Report.
    _write_report(args, prioritized, remediated)

    # 8. Optional: save intermediates for evaluation.
    if args.save_intermediates:
        outdir = Path(args.save_intermediates)
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "enriched.json").write_text(
            json.dumps([f.model_dump() for f in enriched], indent=2)
        )
        (outdir / "scored.json").write_text(json.dumps([f.model_dump() for f in scored], indent=2))
        (outdir / "prioritized.json").write_text(
            json.dumps([f.model_dump() for f in prioritized], indent=2)
        )
        if remediated:
            (outdir / "remediated.json").write_text(
                json.dumps([f.model_dump() for f in remediated], indent=2)
            )
        print(f"[pipeline] intermediates saved to {outdir}")

    return 0


def _write_report(args: argparse.Namespace, prioritized, remediated) -> None:
    """Render the report in the requested format."""
    if args.output_format == "text":
        report = render(prioritized)
        if args.output:
            Path(args.output).write_text(report)
            print(f"[pipeline] report written to {args.output}")
        else:
            print(report)
        return

    # HTML / PDF / both require remediated findings.
    findings = remediated if remediated is not None else prioritized
    if remediated is None:
        print(
            "[pipeline] warning: --output-format html/pdf/both usually needs --remediate; "
            "rendering without remediation fields.",
            file=sys.stderr,
        )

    out_dir = Path(args.output) if args.output else Path("output/reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "report.html" if args.output_format in ("html", "both") else None
    pdf_path = out_dir / "report.pdf" if args.output_format in ("pdf", "both") else None
    written = compose_report(findings, html_path=html_path, pdf_path=pdf_path)
    for fmt, path in written.items():
        print(f"[pipeline] {fmt} report written to {path}")
