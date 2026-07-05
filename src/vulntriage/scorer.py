"""Exploitability Assessor.

Asks the LLM to rate how exploitable each finding is, returning a
High/Medium/Low label with a short rationale. Supports few-shot prompting
(the default, with two worked examples) and zero-shot prompting (examples
omitted) via the ``few_shot`` parameter.
"""

from __future__ import annotations

import json
import re

from .llm import LLMClient
from .models import EnrichedFinding, Exploitability, ScoredFinding

SYSTEM_PROMPT = (
    "You are a senior penetration tester assessing exploitability. "
    "Rate each finding High, Medium, or Low based on: service exposure, "
    "availability of public exploits, attack complexity, and whether the "
    "version is patched. Respond ONLY with a JSON object. No prose outside JSON."
)

# Few-shot examples anchor the label semantics.
FEW_SHOT_BLOCK = """Here are examples of exploitability ratings:

Example 1:
Finding: Open Redis 3.2 without authentication, internet-facing.
Context: Allows unauthenticated access; attackers can read/modify data and
potentially achieve RCE via module upload.
Rating: High

Example 2:
Finding: Internal-only SSH service on a patched version.
Context: No known exploits for the version; requires network access to the
internal segment.
Rating: Low

"""

USER_TEMPLATE = """{few_shot}Now rate this finding:

Host: {host}
Service: {service}
Description: {description}
CVE: {cve}
CVSS: {cvss}
Context: {context}

Provide a JSON object with this exact schema:
{{
  "exploitability": "High|Medium|Low",
  "rationale": "one sentence explaining the rating"
}}

Respond with the JSON object only."""


def score(finding: EnrichedFinding, client: LLMClient, *, few_shot: bool = True) -> ScoredFinding:
    """Score a single finding's exploitability via the LLM.

    Set ``few_shot=False`` to omit the worked examples (zero-shot prompting);
    the default ``True`` preserves the v1 behaviour.
    """
    user = USER_TEMPLATE.format(
        few_shot=FEW_SHOT_BLOCK if few_shot else "",
        host=finding.host,
        service=finding.service or "unknown",
        description=finding.description,
        cve=finding.cve or "none",
        cvss=finding.cvss or "n/a",
        context=finding.context,
    )
    raw_response = client.complete(SYSTEM_PROMPT, user)
    label_str = _extract_json_field(raw_response, "exploitability")
    rationale = _extract_json_field(raw_response, "rationale") or ""
    exploitability = _coerce_label(label_str, finding)
    return ScoredFinding(
        **finding.model_dump(),
        exploitability=exploitability,
        exploitability_rationale=rationale,
        scoring_model=client.model,
    )


def score_all(
    findings: list[EnrichedFinding],
    client: LLMClient,
    *,
    few_shot: bool = True,
) -> list[ScoredFinding]:
    """Score a list of findings, logging progress."""
    scored: list[ScoredFinding] = []
    for i, f in enumerate(findings, 1):
        print(f"[scorer] ({i}/{len(findings)}) {f.id}")
        scored.append(score(f, client, few_shot=few_shot))
    return scored


def _coerce_label(raw: str | None, finding: EnrichedFinding) -> Exploitability:
    """Map the LLM's free-form label to a strict enum value."""
    if raw:
        cleaned = raw.strip().strip('"').strip("'").lower()
        if cleaned.startswith("high"):
            return Exploitability.HIGH
        if cleaned.startswith("medium"):
            return Exploitability.MEDIUM
        if cleaned.startswith("low"):
            return Exploitability.LOW
    # Sensible default: CVSS >= 7.0 -> Medium, otherwise Low.
    if finding.cvss is not None and finding.cvss >= 7.0:
        return Exploitability.MEDIUM
    return Exploitability.LOW


def _extract_json_field(text: str, field: str) -> str | None:
    """Best-effort extraction of a string field from an LLM JSON response."""
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    try:
        obj = json.loads(cleaned)
        val = obj.get(field)
        if isinstance(val, str):
            return val
    except json.JSONDecodeError:
        pass
    pattern = r'"' + field + r'"\s*:\s*"((?:[^"\\]|\\.)*)"'
    match = re.search(pattern, cleaned)
    if match:
        return match.group(1).encode().decode("unicode_escape", errors="replace")
    return None
