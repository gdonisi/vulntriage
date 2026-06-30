"""Tests for the scorer few-shot / zero-shot toggle."""

from __future__ import annotations

from vulntriage.models import EnrichedFinding
from vulntriage.scorer import FEW_SHOT_BLOCK, USER_TEMPLATE, score


class _RecordingClient:
    model = "rec"
    total_tokens = 0

    def __init__(self) -> None:
        self.last_user = ""

    def complete(self, system: str, user: str) -> str:
        self.last_user = user
        return '{"exploitability": "Low", "rationale": "x"}'


def _enriched() -> EnrichedFinding:
    return EnrichedFinding(
        id="e1",
        source="synthetic",
        host="h",
        port=22,
        service="ssh",
        description="OpenSSH patched",
        cvss=3.1,
        cve=None,
        raw={},
        context="ctx",
        enrichment_model="m",
    )


def test_few_shot_prompt_contains_examples():
    c = _RecordingClient()
    score(_enriched(), c, few_shot=True)
    assert "Example 1" in c.last_user
    assert "Example 2" in c.last_user


def test_zero_shot_prompt_omits_examples():
    c = _RecordingClient()
    score(_enriched(), c, few_shot=False)
    assert "Example 1" not in c.last_user
    assert "Example 2" not in c.last_user


def test_template_formats_without_examples():
    rendered = USER_TEMPLATE.format(
        few_shot="",
        host="h",
        service="s",
        description="d",
        cve="n",
        cvss="1",
        context="c",
    )
    assert "Example 1" not in rendered
    assert FEW_SHOT_BLOCK.strip().startswith("Here are examples")


def test_default_few_shot_preserves_v1_behaviour():
    # Default should include examples (v1 behaviour).
    c = _RecordingClient()
    score(_enriched(), c)
    assert "Example 1" in c.last_user
