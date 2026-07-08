"""Pydantic data models for the vulnerability triage pipeline.

Each module takes one of these models and returns the next, forming a linear
pipeline:
    RawFinding -> EnrichedFinding -> ScoredFinding -> PrioritizedFinding -> RemediatedFinding
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Exploitability(StrEnum):
    """Three-tier exploitability label produced by the LLM scorer."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    def numeric(self) -> float:
        """Numeric weight used by the prioritizer formula."""
        return {self.HIGH: 1.0, self.MEDIUM: 0.5, self.LOW: 0.1}[self]


class RawFinding(BaseModel):
    """A normalized vulnerability finding straight from a scanner."""

    id: str
    source: str = Field(description="Scanner that produced this finding: nmap|nuclei|openvas|synthetic")
    host: str
    port: int | None = None
    service: str | None = None
    description: str
    cvss: float | None = None
    cve: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, description="Original scanner record")


class EnrichedFinding(RawFinding):
    """A finding with LLM-generated threat context."""

    context: str = Field(description="Threat model, attack scenarios, business impact")
    enrichment_model: str | None = None


class ScoredFinding(EnrichedFinding):
    """An enriched finding with an exploitability label and rationale.

    The three ``ensemble_*`` fields are populated only when the scorer ran in
    multi-LLM ensemble mode (see ``score_all``). They default to empty/None/
    False so a single-model ``ScoredFinding`` is unaffected and existing
    callers/tests are untouched.
    """

    exploitability: Exploitability
    exploitability_rationale: str = ""
    scoring_model: str | None = None
    # Ensemble only — ``model_name -> label`` for each scoring model.
    exploitability_votes: dict[str, str] = Field(default_factory=dict)
    # Ensemble only — accepted strict-majority quorum threshold.
    ensemble_quorum: int | None = None
    # Ensemble only — True when no label reached quorum (display-only).
    ensemble_unresolved: bool = False


class PrioritizedFinding(ScoredFinding):
    """A scored finding ranked by composite risk score."""

    asset_criticality: float = 0.5
    risk_score: float = 0.0
    rank: int = 0


class RemediatedFinding(PrioritizedFinding):
    """A prioritized finding with LLM-generated remediation steps.

    When light RAG is enabled, ``rag_hits`` lists the CVEs / services whose
    KB entries were injected into the remediation prompt as grounding context.
    """

    remediation_steps: list[str] = Field(default_factory=list)
    remediation_rationale: str = ""
    rag_hits: list[str] = Field(default_factory=list)
    remediation_model: str | None = None
