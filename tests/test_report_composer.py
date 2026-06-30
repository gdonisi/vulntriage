"""Tests for the Final Report Composer (HTML + PDF)."""

from __future__ import annotations

from pathlib import Path

from vulntriage.models import Exploitability, RemediatedFinding
from vulntriage.report_composer import _build_context, compose, render_html, write_pdf

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _remediated(
    i: int, exp: Exploitability, cvss: float, cve: str | None = None
) -> RemediatedFinding:
    return RemediatedFinding(
        id=f"r{i}",
        source="synthetic",
        host=f"192.168.1.{i}",
        port=6379,
        service="redis",
        description=f"Finding number {i}",
        cvss=cvss,
        cve=cve,
        raw={},
        context="Some threat context.",
        enrichment_model="m",
        exploitability=exp,
        exploitability_rationale="rationale",
        scoring_model="m",
        asset_criticality=0.8,
        risk_score=0.9 - i * 0.1,
        rank=i,
        remediation_steps=[f"step {i}a", f"step {i}b"],
        remediation_rationale="Fix it.",
        rag_hits=[cve] if cve else [],
        remediation_model="m",
    )


def test_build_context_counts():
    findings = [
        _remediated(1, Exploitability.HIGH, 9.8, "CVE-2022-0543"),
        _remediated(2, Exploitability.HIGH, 8.1),
        _remediated(3, Exploitability.MEDIUM, 7.5),
        _remediated(4, Exploitability.LOW, 3.1),
    ]
    ctx = _build_context(findings)
    assert ctx["summary"]["total"] == 4
    assert ctx["summary"]["high"] == 2
    assert ctx["summary"]["medium"] == 1
    assert ctx["summary"]["low"] == 1
    assert len(ctx["findings"]) == 4
    assert ctx["findings"][0]["bar_color"] == "#c0392b"


def test_render_html_has_sections():
    findings = [
        _remediated(1, Exploitability.HIGH, 9.8, "CVE-2022-0543"),
        _remediated(2, Exploitability.LOW, 3.1),
    ]
    html = render_html(findings)
    assert "Vulnerability Triage Report" in html
    assert "Executive Summary" in html
    assert "Technical Findings" in html
    assert "Ranked Summary" in html
    assert "CVE-2022-0543" in html


def test_write_pdf_generates_nonempty(tmp_path):
    findings = [
        _remediated(1, Exploitability.HIGH, 9.8, "CVE-2022-0543"),
        _remediated(2, Exploitability.LOW, 3.1),
    ]
    pdf = tmp_path / "report.pdf"
    write_pdf(findings, pdf, template_dir=DATA_DIR / "templates")
    assert pdf.exists()
    assert pdf.stat().st_size > 0
    assert pdf.read_bytes()[:5] == b"%PDF-"


def test_compose_both(tmp_path):
    findings = [_remediated(1, Exploitability.HIGH, 9.8, "CVE-2022-0543")]
    written = compose(
        findings,
        html_path=tmp_path / "report.html",
        pdf_path=tmp_path / "report.pdf",
        template_dir=DATA_DIR / "templates",
    )
    assert "html" in written and "pdf" in written
    assert Path(written["html"]).exists()
    assert Path(written["pdf"]).exists()
