"""Shared test fixtures.

Provides a mock LLM client that inspects the prompt and returns canned
structured-JSON responses for the enricher, scorer, and remediator, so the
full pipeline can be exercised without a real model.
"""

from __future__ import annotations

import json

import pytest


class MockLLMClient:
    """Fake LLMClient that returns canned JSON based on prompt content."""

    model = "mock-model"
    total_tokens = 0

    def complete(self, system: str, user: str) -> str:
        if "remediation guidance" in user or "Remediation Recommendation" in system:
            return json.dumps(
                {
                    "rationale": "Upgrade and harden the service.",
                    "steps": [
                        "Upgrade the vulnerable software",
                        "Enable authentication",
                        "Restrict network access",
                    ],
                }
            )
        if "Rate each finding" in user or "exploitability" in user.lower():
            # Decide a label from the description to keep tests deterministic.
            if "redis" in user.lower() or "log4j" in user.lower() or "jenkins" in user.lower():
                label = "High"
            elif "nginx" in user.lower() or "patched" in user.lower():
                label = "Low"
            else:
                label = "Medium"
            return json.dumps({"exploitability": label, "rationale": "mock rationale"})
        # Enricher default.
        return json.dumps(
            {
                "context": (
                    "Mock threat context: the service is exposed and "
                    "could allow unauthorized access."
                )
            }
        )


@pytest.fixture
def mock_client() -> MockLLMClient:
    return MockLLMClient()
