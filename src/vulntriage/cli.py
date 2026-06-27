"""CLI entry point: orchestrates the full triage pipeline.

    uv run python main.py --input data/synthetic_findings.json \
        --provider lmstudio --model llama-3.2-3b

To run the dockerized Nuclei scanner instead of reading a file:

    uv run python main.py --scan nuclei --target 192.168.1.5 \
        --provider lmstudio --model llama-3.2-3b
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .enricher import enrich_all
from .llm import make_client
from .parser import parse
from .prioritizer import load_asset_registry, prioritize
from .reporter import render
from .scanner import run_nuclei
from .scorer import score_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulntriage",
        description="LLM-enabled vulnerability triage pipeline",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="Path to scanner output (xml/jsonl/json)")
    src.add_argument(
        "--scan",
        choices=["nuclei"],
        help="Run a dockerized scanner against --target",
    )
    p.add_argument("--target", help="Target for --scan")
    p.add_argument(
        "--provider",
        required=True,
        choices=[
            "lmstudio",
            "ollama",
            "llamacpp",
            "vllm",
            "openai",
            "openrouter",
        ],
    )
    p.add_argument("--model", required=True, help="Model name for the chosen provider")
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
    p.add_argument("--output", default=None, help="Write report to this path (default: stdout)")
    p.add_argument(
        "--save-intermediates",
        default=None,
        help="Directory to dump enriched/scored JSON for evaluation",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 1. Acquire scanner results.
    if args.scan == "nuclei":
        if not args.target:
            print("--scan requires --target", file=sys.stderr)
            return 2
        out_path = Path("data/nuclei_scan.jsonl")
        run_nuclei(args.target, out_path)
        input_path = str(out_path)
    else:
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

    # 3. Enrich.
    print("[pipeline] enriching findings...")
    enriched = enrich_all(findings, client)

    # 4. Score exploitability.
    print("[pipeline] scoring exploitability...")
    scored = score_all(enriched, client)

    # 5. Prioritize.
    print("[pipeline] prioritizing...")
    assets = load_asset_registry(args.asset_registry)
    prioritized = prioritize(scored, assets)

    # 6. Report.
    report = render(prioritized)
    if args.output:
        Path(args.output).write_text(report)
        print(f"[pipeline] report written to {args.output}")
    else:
        print(report)

    # 7. Optional: save intermediates for evaluation.
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
        print(f"[pipeline] intermediates saved to {outdir}")

    return 0
