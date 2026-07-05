"""Tests for the multi-LLM ensemble scoring + strict-majority merge."""

from __future__ import annotations

import json

from vulntriage.models import EnrichedFinding
from vulntriage.scorer import _strict_majority, score_all


class _Client:
    """Mock client returning a fixed exploitability label regardless of input."""

    total_tokens = 0

    def __init__(self, model: str, label: str) -> None:
        self.model = model
        self._label = label

    def complete(self, system: str, user: str) -> str:
        return json.dumps({"exploitability": self._label, "rationale": "mock"})


def _enriched() -> EnrichedFinding:
    return EnrichedFinding(
        id="e1",
        source="synthetic",
        host="h",
        port=6379,
        service="redis",
        description="Open Redis without auth",
        cvss=9.8,
        cve="CVE-2022-0543",
        raw={},
        context="ctx",
        enrichment_model="m",
    )


def test_strict_majority_resolves_when_quorum_met():
    # 3 models: 2 High, 1 Medium -> quorum 2 -> High resolved.
    votes = {"a": "High", "b": "High", "c": "Medium"}
    label, rationale, unresolved = _strict_majority(votes, None)
    assert not unresolved
    assert label.value == "High"
    assert "2/3" in rationale
    assert "quorum 2" in rationale


def test_strict_majority_unresolved_when_no_quorum():
    # 3 models split 3 ways -> quorum 2 -> no winner.
    votes = {"a": "High", "b": "Medium", "c": "Low"}
    label, rationale, unresolved = _strict_majority(votes, None)
    assert unresolved
    # Fallback label is the highest tally winner (first by count==1 tie; deterministic
    # order is the iteration order of votes -> 'High' first).
    assert "unresolved" in rationale
    assert label.value in ("High", "Medium", "Low")  # still set for the prioritizer


def test_strict_majority_even_n_requires_unanimity():
    # 2 models: 1 High, 1 Medium -> quorum 2 -> unresolved.
    votes = {"a": "High", "b": "Medium"}
    _, _, unresolved = _strict_majority(votes, None)
    assert unresolved


def test_explicit_quorum_overrides_default():
    # 3 models: 2 High, 1 Medium -> explicit quorum 3 -> unresolved.
    votes = {"a": "High", "b": "High", "c": "Medium"}
    _, _, unresolved = _strict_majority(votes, 3)
    assert unresolved


def test_score_all_single_client_path_unchanged():
    # With no `clients`, score_all behaves exactly as before (no votes recorded).
    c = _Client("m", "High")
    out = score_all([_enriched()], c)
    assert len(out) == 1
    assert out[0].exploitability.value == "High"
    assert out[0].exploitability_votes == {}
    assert out[0].ensemble_quorum is None
    assert out[0].ensemble_unresolved is False


def test_score_all_ensemble_resolves_with_agreement():
    primary = _Client("primary", "High")
    a = _Client("a", "High")
    b = _Client("b", "Medium")
    # 3 models, 2 High -> resolved High.
    out = score_all([_enriched()], primary, clients=[primary, a, b])
    f = out[0]
    assert f.ensemble_unresolved is False
    assert f.exploitability.value == "High"
    assert f.exploitability_votes == {"primary": "High", "a": "High", "b": "Medium"}
    assert f.ensemble_quorum == 2


def test_score_all_ensemble_unresolved_on_split():
    # Three models disagreeing fully -> unresolved.
    primary = _Client("primary", "High")
    a = _Client("a", "Medium")
    b = _Client("b", "Low")
    out = score_all([_enriched()], primary, clients=[primary, a, b])
    f = out[0]
    assert f.ensemble_unresolved is True
    assert len(f.exploitability_votes) == 3


def test_score_all_ensemble_explicit_quorum():
    primary = _Client("primary", "High")
    a = _Client("a", "High")
    b = _Client("b", "Medium")
    # quorum 3 forces unresolved even though 2 agree High.
    out = score_all([_enriched()], primary, clients=[primary, a, b], quorum=3)
    assert out[0].ensemble_unresolved is True
    assert out[0].ensemble_quorum == 3
