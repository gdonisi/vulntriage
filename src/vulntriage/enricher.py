"""Finding Context Enhancer.

Asks the LLM to expand a raw finding with threat context: what is vulnerable,
why it's risky, real-world attack scenarios, and business impact. Returns
structured JSON parsed into EnrichedFinding.
"""

from __future__ import annotations

import json
import re

from .llm import LLMClient
from .models import EnrichedFinding, RawFinding

SYSTEM_PROMPT = (
    "You are a senior security analyst. For each vulnerability finding, produce "
    "a concise threat analysis. Respond ONLY with a JSON object matching the "
    "schema. No prose outside the JSON."
)

USER_TEMPLATE = """Analyze this vulnerability finding:

Host: {host}
Port: {port}
Service: {service}
Description: {description}
CVE: {cve}
CVSS: {cvss}

Provide a JSON object with this exact schema:
{{
  "context": "3-4 sentences covering: what is vulnerable, real-world attack "
            "scenarios, and business impact"
}}

Respond with the JSON object only."""


def enrich(finding: RawFinding, client: LLMClient) -> EnrichedFinding:
    """Enrich a single finding via the LLM."""
    user = USER_TEMPLATE.format(
        host=finding.host,
        port=finding.port or "n/a",
        service=finding.service or "unknown",
        description=finding.description,
        cve=finding.cve or "none",
        cvss=finding.cvss or "n/a",
    )
    raw_response = client.complete(SYSTEM_PROMPT, user)
    context = _extract_json_field(raw_response, "context")
    if not context:
        context = raw_response.strip()
    return EnrichedFinding(
        **finding.model_dump(),
        context=context,
        enrichment_model=client.model,
    )


def enrich_all(findings: list[RawFinding], client: LLMClient) -> list[EnrichedFinding]:
    """Enrich a list of findings, logging progress."""
    enriched: list[EnrichedFinding] = []
    for i, f in enumerate(findings, 1):
        print(f"[enricher] ({i}/{len(findings)}) {f.id}")
        enriched.append(enrich(f, client))
    return enriched


def _extract_json_field(text: str, field: str) -> str | None:
    """Best-effort extraction of a string field from an LLM JSON response."""
    # Strip code fences if present.
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    try:
        obj = json.loads(cleaned)
        val = obj.get(field)
        if isinstance(val, str):
            return val
    except json.JSONDecodeError:
        pass
    # Fallback: regex for "context": "..."
    pattern = r'"' + field + r'"\s*:\s*"((?:[^"\\]|\\.)*)"'
    match = re.search(pattern, cleaned)
    if match:
        return match.group(1).encode().decode("unicode_escape", errors="replace")
    return None
