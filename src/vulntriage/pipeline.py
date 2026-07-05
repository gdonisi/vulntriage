"""Shared triage pipeline execution — used by both the CLI and the webapp.

This module holds the body of a single triage run (parse-merge-Enrich-score-
prioritize-remediate-compose + intermediates), factored out of ``cli.main`` so
the webapp worker can drive the same logic without re-implementing it. The CLI
remains responsible for argument parsing, input acquisition, and building the
LLM client; everything after the client exists lives here.

Behaviour is identical to calling the CLI on the same inputs: reports land in
``out_dir``, intermediates (when requested) in ``out_dir/intermediates/``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .enricher import enrich_all
from .llm import LLMClient
from .models import PrioritizedFinding, RawFinding, RemediatedFinding
from .prioritizer import load_asset_registry, prioritize
from .remediator import remediate_all
from .report_composer import compose as compose_report
from .reporter import render
from .scorer import score_all


@dataclass
class RunResult:
    """Outputs and artifacts of a single triage run."""

    run_dir: Path
    enriched: list = field(default_factory=list)
    scored: list = field(default_factory=list)
    prioritized: list[PrioritizedFinding] = field(default_factory=list)
    remediated: list[RemediatedFinding] | None = None
    # "html" and/or "pdf" -> path written (text goes to stdout/text_output).
    written: dict[str, str] = field(default_factory=dict)
    text_report: str | None = None
    intermediates_dir: Path | None = None


def write_intermediates(
    inter_dir: Path,
    enriched: list,
    scored: list,
    prioritized: Sequence[PrioritizedFinding],
    remediated: list[RemediatedFinding] | None,
) -> Path:
    """Dump enriched/scored/prioritized/remediated JSON directly into *inter_dir*."""
    inter_dir.mkdir(parents=True, exist_ok=True)
    (inter_dir / "enriched.json").write_text(
        json.dumps([f.model_dump() for f in enriched], indent=2)
    )
    (inter_dir / "scored.json").write_text(json.dumps([f.model_dump() for f in scored], indent=2))
    (inter_dir / "prioritized.json").write_text(
        json.dumps([f.model_dump() for f in prioritized], indent=2)
    )
    if remediated:
        (inter_dir / "remediated.json").write_text(
            json.dumps([f.model_dump() for f in remediated], indent=2)
        )
    return inter_dir


def save_intermediates(
    out_dir: Path,
    enriched: list,
    scored: list,
    prioritized: Sequence[PrioritizedFinding],
    remediated: list[RemediatedFinding] | None,
) -> Path:
    """Dump enriched/scored/prioritized/remediated JSON under ``out_dir/intermediates/``."""
    return write_intermediates(out_dir / "intermediates", enriched, scored, prioritized, remediated)


def run_pipeline(
    findings: list[RawFinding],
    client: LLMClient,
    *,
    out_dir: str | Path,
    output_format: str = "text",
    remediate: bool = False,
    use_rag: bool = True,
    kb_path: str | Path | None = "data/cve_kb.json",
    prompt_strategy: str = "few-shot",
    asset_registry: str | Path | None = None,
    save_intermediates_flag: bool = False,
    intermediates_dir: str | Path | None = None,
    text_output: str | Path | None = None,
    # Ensemble: fan out only the exploitability scorer across these clients.
    # ``client`` remains the primary (used for enrichment + remediation and as
    # the first ensemble member). See ``scorer.score_all`` for the merge rule.
    scoring_clients: list[LLMClient] | None = None,
    scoring_quorum: int | None = None,
) -> RunResult:
    """Run a single triage pass on *findings* and write artifacts to *out_dir*.

    Parameters mirror the CLI flags; ``text_output`` is the file path for the
    text report (``None`` returns the text instead of writing it). When
    ``save_intermediates_flag`` is set, intermediates go to
    ``intermediates_dir`` if given, else ``out_dir/intermediates/``.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    few_shot = prompt_strategy == "few-shot"

    print(f"[pipeline] {len(findings)} finding(s) after merge")

    # 1. Enrich.
    print("[pipeline] enriching findings...")
    enriched = enrich_all(findings, client)

    # 2. Score exploitability. If a scoring ensemble is supplied, only this
    # step fans out (multiple models); enrichment/remediation stay single-model.
    if scoring_clients:
        print(
            f"[pipeline] scoring exploitability (ensemble of {len(scoring_clients)} "
            f"model(s), quorum={scoring_quorum or (len(scoring_clients) // 2 + 1)}, "
            f"prompt strategy: {prompt_strategy})..."
        )
        scored = score_all(
            enriched,
            client,
            few_shot=few_shot,
            clients=scoring_clients,
            quorum=scoring_quorum,
        )
    else:
        print(f"[pipeline] scoring exploitability (prompt strategy: {prompt_strategy})...")
        scored = score_all(enriched, client, few_shot=few_shot)

    # 3. Prioritize.
    print("[pipeline] prioritizing...")
    assets = load_asset_registry(asset_registry)
    prioritized = prioritize(scored, assets)

    # 4. Remediate (optional, v2).
    remediated: list[RemediatedFinding] | None = None
    if remediate:
        rag_label = "on" if use_rag else "off"
        print(f"[pipeline] generating remediation (RAG: {rag_label})...")
        remediated = remediate_all(prioritized, client, kb_path=kb_path, use_rag=use_rag)

    # 5. Report.
    written: dict[str, str] = {}
    text_report: str | None = None
    if output_format == "text":
        report = render(prioritized)
        if text_output:
            Path(text_output).parent.mkdir(parents=True, exist_ok=True)
            Path(text_output).write_text(report)
            print(f"[pipeline] report written to {text_output}")
            written["text"] = str(text_output)
        else:
            text_report = report
    else:
        report_findings = remediated if remediated is not None else prioritized
        if remediated is None:
            print(
                "[pipeline] note: rendering HTML/PDF without remediation; "
                "remediation sections will be empty.",
                file=__import__("sys").stderr,
            )
        html_path = out_dir / "report.html" if output_format in ("html", "both") else None
        pdf_path = out_dir / "report.pdf" if output_format in ("pdf", "both") else None
        written = compose_report(report_findings, html_path=html_path, pdf_path=pdf_path)
        for fmt, path in written.items():
            print(f"[pipeline] {fmt} report written to {path}")

    # 6. Intermediates.
    intermediates_out: Path | None = None
    if save_intermediates_flag:
        if intermediates_dir:
            intermediates_out = write_intermediates(
                Path(intermediates_dir), enriched, scored, prioritized, remediated
            )
        else:
            intermediates_out = save_intermediates(
                out_dir, enriched, scored, prioritized, remediated
            )
        print(f"[pipeline] intermediates saved to {intermediates_out}")

    return RunResult(
        run_dir=out_dir,
        enriched=enriched,
        scored=scored,
        prioritized=prioritized,
        remediated=remediated,
        written=written,
        text_report=text_report,
        intermediates_dir=intermediates_out,
    )
