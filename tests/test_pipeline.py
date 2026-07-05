"""Tests for the extracted run_pipeline() function (shared by CLI and webapp)."""

from __future__ import annotations

import json
from pathlib import Path

from vulntriage.models import RawFinding
from vulntriage.pipeline import run_pipeline, save_intermediates, write_intermediates

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class _MockClient:
    model = "mock"
    total_tokens = 0

    def complete(self, system: str, user: str) -> str:
        if "remediation guidance" in user or "senior security engineer" in system:
            return json.dumps({"rationale": "Fix it.", "steps": ["Upgrade", "Restrict access"]})
        if "exploitability" in user.lower() or "rate this finding" in user.lower():
            return json.dumps({"exploitability": "High", "rationale": "mock"})
        return json.dumps({"context": "Mock threat context."})


def _findings() -> list[RawFinding]:
    data = json.loads((DATA_DIR / "synthetic_findings.json").read_text())
    out: list[RawFinding] = []
    for i, item in enumerate(data):
        out.append(
            RawFinding(
                id=item.get("id", f"synthetic-{i}"),
                source="synthetic",
                host=item.get("host", "unknown"),
                port=item.get("port"),
                service=item.get("service"),
                description=item["description"],
                cvss=item.get("cvss"),
                cve=item.get("cve"),
                raw=item,
            )
        )
    return out


def test_run_pipeline_html_pdf(tmp_path):
    findings = _findings()
    result = run_pipeline(
        findings,
        _MockClient(),
        out_dir=tmp_path / "run",
        output_format="both",
        remediate=True,
        asset_registry=str(DATA_DIR / "assets.yaml"),
    )
    assert result.run_dir.exists()
    assert (result.run_dir / "report.html").exists()
    assert (result.run_dir / "report.pdf").read_bytes()[:5] == b"%PDF-"
    assert len(result.prioritized) == 20
    assert result.remediated is not None and len(result.remediated) == 20


def test_run_pipeline_text_stdout(tmp_path):
    result = run_pipeline(
        _findings()[:3],
        _MockClient(),
        out_dir=tmp_path / "run",
        output_format="text",
        asset_registry=str(DATA_DIR / "assets.yaml"),
    )
    assert result.text_report is not None
    assert "VULNERABILITY TRIAGE REPORT" in result.text_report
    assert not (tmp_path / "run" / "report.html").exists()


def test_run_pipeline_intermediates_default(tmp_path):
    result = run_pipeline(
        _findings()[:3],
        _MockClient(),
        out_dir=tmp_path / "run",
        output_format="html",
        save_intermediates_flag=True,
    )
    assert result.intermediates_dir == (tmp_path / "run" / "intermediates")
    assert (result.intermediates_dir / "enriched.json").exists()
    assert (result.intermediates_dir / "scored.json").exists()


def test_write_intermediates_explicit_dir(tmp_path):
    d = tmp_path / "custom"
    write_intermediates(d, [], [], [], None)
    assert (d / "enriched.json").exists()
    assert not (d / "intermediates").exists()


def test_write_intermediates_via_save_helper(tmp_path):
    d = save_intermediates(tmp_path / "run", [], [], [], None)
    assert d == (tmp_path / "run" / "intermediates")
    assert (d / "enriched.json").exists()


def test_run_pipeline_remediate_off(tmp_path):
    result = run_pipeline(
        _findings()[:2],
        _MockClient(),
        out_dir=tmp_path / "run",
        output_format="html",
        remediate=False,
    )
    assert result.remediated is None
