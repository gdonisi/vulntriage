"""Tests for the Final Report Composer (HTML + PDF)."""

from __future__ import annotations

from pathlib import Path

from vulntriage.models import Exploitability, PrioritizedFinding, RemediatedFinding
from vulntriage.report_composer import _build_context, compose, render_html, write_pdf

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _remediated(
    i: int,
    exp: Exploitability,
    cvss: float,
    cve: str | None = None,
    *,
    risk: float | None = None,
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
        risk_score=risk if risk is not None else 0.9 - i * 0.1,
        rank=i,
        remediation_steps=[f"step {i}a", f"step {i}b"],
        remediation_rationale="Fix it.",
        rag_hits=[cve] if cve else [],
        remediation_model="m",
    )


def _prioritized(
    i: int, exp: Exploitability, cvss: float, *, risk: float, rank: int
) -> PrioritizedFinding:
    return PrioritizedFinding(
        id=f"p{i}",
        source="synthetic",
        host=f"192.168.1.{i}",
        port=6379,
        service="redis",
        description=f"Finding number {i}",
        cvss=cvss,
        raw={},
        context="Some threat context.",
        enrichment_model="m",
        exploitability=exp,
        exploitability_rationale="rationale",
        scoring_model="m",
        asset_criticality=0.8,
        risk_score=risk,
        rank=rank,
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


def test_bar_widths_scale_with_risk_score():
    """Risk-breakdown bar fill widths must reflect the risk score, not be equal."""
    import re

    findings = [
        _remediated(1, Exploitability.HIGH, 9.8, risk=0.85),
        _remediated(2, Exploitability.LOW, 3.1, risk=0.15),
    ]
    html = render_html(findings, template_dir=DATA_DIR / "templates")
    widths = [float(m.group(1)) for m in re.finditer(r'bar-fill" style="width: ([\d.]+)%', html)]
    assert len(widths) == 2
    assert widths[0] > widths[1]
    assert widths[0] == 85.0
    assert widths[1] == 15.0


def test_render_html_without_remediation():
    """HTML report must render from PrioritizedFinding (no --remediate) without crashing."""
    findings = [
        _prioritized(1, Exploitability.HIGH, 9.8, risk=0.85, rank=1),
        _prioritized(2, Exploitability.LOW, 3.1, risk=0.15, rank=2),
    ]
    html = render_html(findings, template_dir=DATA_DIR / "templates")
    assert "Technical Findings" in html
    assert "Ranked Summary" in html
    # No remediation steps should be rendered for non-remediated findings.
    assert "Remediation:" not in html
