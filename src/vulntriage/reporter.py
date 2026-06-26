"""Final Report Composer (plain-text v1).

Produces a simple ranked text report: a summary line, per-finding detail,
and a final ranked table.
"""

from __future__ import annotations

from .models import PrioritizedFinding


def render(findings: list[PrioritizedFinding]) -> str:
    """Render findings as a plain-text prioritized report."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("VULNERABILITY TRIAGE REPORT")
    lines.append("=" * 72)
    lines.append(f"Total findings: {len(findings)}")
    if findings:
        high = sum(1 for f in findings if f.exploitability.value == "High")
        med = sum(1 for f in findings if f.exploitability.value == "Medium")
        low = sum(1 for f in findings if f.exploitability.value == "Low")
        lines.append(f"Exploitability: {high} High, {med} Medium, {low} Low")
    lines.append("")

    for f in findings:
        lines.append("-" * 72)
        lines.append(f"#{f.rank} [{f.exploitability.value}] {f.description}")
        lines.append(f"  Host: {f.host}" + (f"  Port: {f.port}" if f.port else ""))
        if f.cve:
            lines.append(f"  CVE: {f.cve}")
        if f.cvss is not None:
            lines.append(f"  CVSS: {f.cvss}")
        lines.append(f"  Risk Score: {f.risk_score} (asset criticality: {f.asset_criticality})")
        lines.append(f"  Context: {f.context}")
        lines.append(f"  Exploitability rationale: {f.exploitability_rationale}")
        lines.append("")

    lines.append("-" * 72)
    lines.append("RANKED SUMMARY")
    lines.append("-" * 72)
    lines.append(f"{'Rank':<5} {'Score':<7} {'Exploit':<8} {'Finding'}")
    for f in findings:
        lines.append(f"{f.rank:<5} {f.risk_score:<7} {f.exploitability.value:<8} {f.description}")
    lines.append("=" * 72)
    return "\n".join(lines)
