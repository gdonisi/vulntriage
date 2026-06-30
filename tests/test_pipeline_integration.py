"""End-to-end integration test of the v2 pipeline using a mock LLM client.

Verifies the wiring: parse -> enrich -> score -> prioritize -> remediate ->
compose (HTML + PDF), without needing a real model.
"""

from __future__ import annotations

from pathlib import Path

from vulntriage.enricher import enrich_all
from vulntriage.models import RemediatedFinding
from vulntriage.prioritizer import load_asset_registry, prioritize
from vulntriage.remediator import remediate_all
from vulntriage.report_composer import compose
from vulntriage.scorer import score_all

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def test_full_pipeline_with_mock_client(mock_client, tmp_path):
    from vulntriage.parser import parse

    findings = parse(str(DATA_DIR / "synthetic_findings.json"))
    assert len(findings) == 20

    enriched = enrich_all(findings, mock_client)
    assert all(f.context for f in enriched)

    scored = score_all(enriched, mock_client, few_shot=True)
    assert all(f.exploitability for f in scored)

    assets = load_asset_registry(DATA_DIR / "assets.yaml")
    prioritized = prioritize(scored, assets)
    assert prioritized[0].rank == 1
    assert prioritized[0].risk_score >= prioritized[-1].risk_score

    remediated = remediate_all(
        prioritized, mock_client, kb_path=DATA_DIR / "cve_kb.json", use_rag=True
    )
    assert len(remediated) == 20
    assert all(isinstance(f, RemediatedFinding) for f in remediated)
    # Findings with a CVE in the KB should have rag_hits populated.
    redis = next(f for f in remediated if f.cve == "CVE-2022-0543")
    assert "CVE-2022-0543" in redis.rag_hits

    written = compose(
        remediated,
        html_path=tmp_path / "report.html",
        pdf_path=tmp_path / "report.pdf",
        template_dir=DATA_DIR / "templates",
    )
    assert Path(written["html"]).exists()
    assert Path(written["pdf"]).exists()
    assert Path(written["pdf"]).read_bytes()[:5] == b"%PDF-"


def test_pipeline_zero_shot_and_no_rag(mock_client):
    from vulntriage.parser import parse

    findings = parse(str(DATA_DIR / "synthetic_findings.json"))[:3]
    enriched = enrich_all(findings, mock_client)
    scored = score_all(enriched, mock_client, few_shot=False)
    assert len(scored) == 3

    assets = load_asset_registry(DATA_DIR / "assets.yaml")
    prioritized = prioritize(scored, assets)
    remediated = remediate_all(
        prioritized, mock_client, kb_path=DATA_DIR / "cve_kb.json", use_rag=False
    )
    # RAG off -> no rag_hits.
    assert all(f.rag_hits == [] for f in remediated)
