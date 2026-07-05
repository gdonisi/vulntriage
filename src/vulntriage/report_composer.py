"""Final Report Composer (v2).

Renders prioritized, remediated findings into an HTML report (via Jinja2) and
a PDF report (via WeasyPrint). Both formats share a single HTML template.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import PrioritizedFinding

_DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "templates"
_DEFAULT_TEMPLATE_NAME = "report.html"

_BAR_COLORS = {"High": "#c0392b", "Medium": "#d68910", "Low": "#1e8449"}


def _build_context(findings: Sequence[PrioritizedFinding]) -> dict:
    """Build the Jinja2 context dict from a list of findings.

    Accepts ``RemediatedFinding`` (full report) or plain ``PrioritizedFinding``
    (HTML/PDF report rendered without ``--remediate``); remediation fields are
    read via ``getattr`` so the template renders with empty remediation
    sections when the finding was not remediated.
    """
    high = sum(
        1
        for f in findings
        if f.exploitability.value == "High" and not getattr(f, "ensemble_unresolved", False)
    )
    medium = sum(
        1
        for f in findings
        if f.exploitability.value == "Medium" and not getattr(f, "ensemble_unresolved", False)
    )
    low = sum(
        1
        for f in findings
        if f.exploitability.value == "Low" and not getattr(f, "ensemble_unresolved", False)
    )
    unresolved = sum(1 for f in findings if getattr(f, "ensemble_unresolved", False))
    top = findings[0] if findings else None

    # Detect ensemble mode from any finding carrying votes.
    ensemble = any(getattr(f, "exploitability_votes", {}) for f in findings)
    quorum = next(
        (
            getattr(f, "ensemble_quorum", None)
            for f in findings
            if getattr(f, "ensemble_quorum", None) is not None
        ),
        None,
    )
    n_models = max((len(getattr(f, "exploitability_votes", {})) for f in findings), default=0)
    executive_text = (
        f"This report covers {len(findings)} vulnerability finding(s) triaged by the "
        f"LLM-driven pipeline. Of these, {high} are rated High exploitability, "
        f"{medium} Medium, and {low} Low. "
    )
    if ensemble:
        executive_text += (
            f"Exploitability was scored by a {n_models}-model ensemble "
            f"(strict-majority quorum {quorum}); {unresolved} finding(s) were "
            "Unresolved (no label reached the quorum) and flagged for review. "
        )
    if top:
        executive_text += (
            f"The highest-priority finding is: {top.description} "
            f"(host {top.host}, risk score {top.risk_score}). "
        )
    executive_text += (
        "Findings are ranked by a composite risk score combining CVSS, LLM-assessed "
        "exploitability, and asset criticality. Recommended remediation steps follow each finding."
    )

    finding_dicts = []
    for f in findings:
        finding_dicts.append(
            {
                "rank": f.rank,
                "description": f.description,
                "host": f.host,
                "port": f.port,
                "cve": f.cve,
                "cvss": f.cvss,
                "risk_score": f.risk_score,
                "asset_criticality": f.asset_criticality,
                "exploitability": (
                    "Unresolved"
                    if getattr(f, "ensemble_unresolved", False)
                    else f.exploitability.value
                ),
                # stable High/Med/Low for badge color
                "exploitability_class": f.exploitability.value,
                "ensemble_unresolved": getattr(f, "ensemble_unresolved", False),
                "exploitability_votes": getattr(f, "exploitability_votes", {}),
                "context": f.context,
                "exploitability_rationale": f.exploitability_rationale,
                "remediation_steps": getattr(f, "remediation_steps", []),
                "remediation_rationale": getattr(f, "remediation_rationale", ""),
                "rag_hits": getattr(f, "rag_hits", []),
                "bar_color": _BAR_COLORS.get(f.exploitability.value, "#888"),
            }
        )

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "summary": {
            "total": len(findings),
            "high": high,
            "medium": medium,
            "low": low,
            "unresolved": unresolved,
            "ensemble": ensemble,
            "n_models": n_models if ensemble else 0,
            "quorum": quorum if ensemble else None,
            "executive_text": executive_text,
        },
        "findings": finding_dicts,
    }


def _make_env(template_dir: str | Path | None = None) -> Environment:
    tdir = Path(template_dir) if template_dir else _DEFAULT_TEMPLATE_DIR
    return Environment(
        loader=FileSystemLoader(str(tdir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(
    findings: Sequence[PrioritizedFinding],
    *,
    template_dir: str | Path | None = None,
) -> str:
    """Render findings to an HTML string."""
    env = _make_env(template_dir)
    template = env.get_template(_DEFAULT_TEMPLATE_NAME)
    return template.render(**_build_context(findings))


def write_html(
    findings: Sequence[PrioritizedFinding],
    path: str | Path,
    *,
    template_dir: str | Path | None = None,
) -> Path:
    """Render findings to HTML and write to *path*."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(findings, template_dir=template_dir))
    return out


def write_pdf(
    findings: Sequence[PrioritizedFinding],
    path: str | Path,
    *,
    template_dir: str | Path | None = None,
) -> Path:
    """Render findings to PDF via WeasyPrint and write to *path*."""
    from weasyprint import HTML

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    html_str = render_html(findings, template_dir=template_dir)
    HTML(string=html_str).write_pdf(str(out))
    return out


def compose(
    findings: Sequence[PrioritizedFinding],
    html_path: str | Path | None = None,
    pdf_path: str | Path | None = None,
    *,
    template_dir: str | Path | None = None,
) -> dict:
    """Render HTML and/or PDF reports as requested.

    Returns a dict mapping ``"html"`` and/or ``"pdf"`` to the written paths.
    """
    written: dict = {}
    if html_path:
        written["html"] = str(write_html(findings, html_path, template_dir=template_dir))
    if pdf_path:
        written["pdf"] = str(write_pdf(findings, pdf_path, template_dir=template_dir))
    return written
