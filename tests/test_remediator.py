"""Tests for the Remediation Recommendation Generator (light RAG)."""

from __future__ import annotations

import json
from pathlib import Path

from vulntriage.models import Exploitability, PrioritizedFinding
from vulntriage.remediator import load_kb, lookup, remediate, remediate_all

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
KB_PATH = DATA_DIR / "cve_kb.json"


def _finding(cve: str | None = None, service: str = "redis") -> PrioritizedFinding:
    return PrioritizedFinding(
        id="t1",
        source="synthetic",
        host="192.168.1.10",
        port=6379,
        service=service,
        description="Open Redis without auth",
        cvss=9.8,
        cve=cve,
        raw={},
        context="ctx",
        exploitability=Exploitability.HIGH,
        exploitability_rationale="r",
        scoring_model="m",
        asset_criticality=1.0,
        risk_score=0.99,
        rank=1,
    )


class StubClient:
    model = "stub"
    total_tokens = 0

    def __init__(self) -> None:
        self.last_user = ""

    def complete(self, system: str, user: str) -> str:
        self.last_user = user
        return json.dumps({"rationale": "fix it", "steps": ["step one", "step two"]})


def test_load_kb_real_file():
    kb = load_kb(KB_PATH)
    assert len(kb) > 0
    assert all("remediation_steps" in e for e in kb)


def test_lookup_by_cve():
    kb = load_kb(KB_PATH)
    hits = lookup(kb, cve="CVE-2022-0543", service="redis")
    assert len(hits) == 1
    assert hits[0]["cve"] == "CVE-2022-0543"


def test_lookup_service_fallback():
    kb = load_kb(KB_PATH)
    hits = lookup(kb, cve=None, service="mongodb")
    assert len(hits) >= 1
    assert hits[0]["cve"] is None


def test_lookup_unknown_returns_empty():
    kb = load_kb(KB_PATH)
    assert lookup(kb, cve="CVE-9999-9999", service="nonexistent") == []


def test_remediate_with_rag_injects_grounding():
    kb = load_kb(KB_PATH)
    client = StubClient()
    finding = _finding(cve="CVE-2022-0543")
    result = remediate(finding, client, kb, use_rag=True)
    assert "CVE-2022-0543" in client.last_user
    assert result.rag_hits == ["CVE-2022-0543"]
    assert result.remediation_steps == ["step one", "step two"]
    assert result.remediation_model == "stub"


def test_remediate_without_rag_no_grounding():
    kb = load_kb(KB_PATH)
    client = StubClient()
    finding = _finding(cve="CVE-2022-0543")
    result = remediate(finding, client, kb, use_rag=False)
    assert "Reference knowledge base" not in client.last_user
    assert result.rag_hits == []
    assert result.remediation_steps == ["step one", "step two"]


def test_remediate_all_progress(mock_client):
    findings = [_finding(cve="CVE-2022-0543"), _finding(cve="CVE-2021-44228", service="http")]
    results = remediate_all(findings, mock_client, kb_path=KB_PATH, use_rag=True)
    assert len(results) == 2
    assert all(r.remediation_steps for r in results)
