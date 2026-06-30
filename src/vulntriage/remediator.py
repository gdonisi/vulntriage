"""Remediation Recommendation Generator.

Asks the LLM to produce concrete, step-by-step fix suggestions for each
prioritized finding. Optionally grounds the prompt in a small curated
knowledge base (light RAG): before the call we look up the finding's CVE and
service in ``data/cve_kb.json`` and inject matching remediation context.

RAG is toggled with ``use_rag``; when ``False`` (or when no KB hits are found)
the LLM generates remediation purely from its own knowledge.
"""

from __future__ import annotations

import json
from pathlib import Path

from .json_utils import parse_json_object
from .llm import LLMClient
from .models import PrioritizedFinding, RemediatedFinding

SYSTEM_PROMPT = (
    "You are a senior security engineer writing remediation guidance. For each "
    "vulnerability, produce a short rationale followed by concrete, ordered, "
    "actionable remediation steps grounded in vendor advisories and best "
    "practices. Respond ONLY with a JSON object matching the schema. No prose "
    "outside the JSON."
)

USER_TEMPLATE = """{grounding}Generate remediation guidance for this finding:

Host: {host}
Service: {service}
Description: {description}
CVE: {cve}
CVSS: {cvss}
Exploitability: {exploitability}
Risk score: {risk_score}

Provide a JSON object with this exact schema:
{{
  "rationale": "one sentence summarising the remediation approach",
  "steps": ["step 1", "step 2", "..."]
}}

Respond with the JSON object only."""


def load_kb(path: str | Path) -> list[dict]:
    """Load the curated remediation knowledge base from a JSON file."""
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    return data if isinstance(data, list) else []


def lookup(kb: list[dict], cve: str | None = None, service: str | None = None) -> list[dict]:
    """Return KB entries matching the finding.

    Matches by CVE first (highest specificity). If no CVE match is found, or
    no CVE is given, falls back to entries keyed by service. Returns an empty
    list when nothing matches.
    """
    hits: list[dict] = []
    if cve:
        hits = [e for e in kb if e.get("cve") and e["cve"] == cve]
    if not hits and service:
        # Service-class entries have cve == null.
        hits = [e for e in kb if e.get("cve") is None and e.get("service") == service]
    return hits


def _format_grounding(hits: list[dict]) -> str:
    """Render KB hits as grounding context for the LLM prompt."""
    if not hits:
        return ""
    blocks: list[str] = []
    for h in hits:
        steps = "\n".join(f"  - {s}" for s in h.get("remediation_steps", []))
        ref = h["cve"] if h.get("cve") else f"service:{h.get('service', 'unknown')}"
        blocks.append(
            f"Reference knowledge base entry ({ref}):\n"
            f"Summary: {h.get('summary', '')}\n"
            f"Known remediation steps:\n{steps}\n"
        )
    return "Use this reference guidance where applicable:\n\n" + "\n".join(blocks) + "\n"


def remediate(
    finding: PrioritizedFinding,
    client: LLMClient,
    kb: list[dict] | None = None,
    *,
    use_rag: bool = True,
) -> RemediatedFinding:
    """Generate remediation steps for a single finding via the LLM.

    When ``use_rag`` is ``True`` and ``kb`` is provided, matching KB entries
    are injected into the prompt as grounding context and their CVEs/services
    are recorded in ``rag_hits``.
    """
    hits: list[dict] = []
    if use_rag and kb:
        hits = lookup(kb, cve=finding.cve, service=finding.service)

    grounding = _format_grounding(hits)
    rag_hits = [h["cve"] for h in hits if h.get("cve")] + [
        f"service:{h['service']}" for h in hits if not h.get("cve") and h.get("service")
    ]

    user = USER_TEMPLATE.format(
        grounding=grounding,
        host=finding.host,
        service=finding.service or "unknown",
        description=finding.description,
        cve=finding.cve or "none",
        cvss=finding.cvss if finding.cvss is not None else "n/a",
        exploitability=finding.exploitability.value,
        risk_score=finding.risk_score,
    )
    raw_response = client.complete(SYSTEM_PROMPT, user)

    obj = parse_json_object(raw_response) or {}
    raw_steps = obj.get("steps")
    steps = raw_steps if isinstance(raw_steps, list) else []
    steps = [str(s) for s in steps if s]
    raw_rationale = obj.get("rationale")
    rationale = raw_rationale if isinstance(raw_rationale, str) else ""

    return RemediatedFinding(
        **finding.model_dump(),
        remediation_steps=steps,
        remediation_rationale=rationale,
        rag_hits=rag_hits,
        remediation_model=client.model,
    )


def remediate_all(
    findings: list[PrioritizedFinding],
    client: LLMClient,
    kb_path: str | Path | None = None,
    *,
    use_rag: bool = True,
) -> list[RemediatedFinding]:
    """Remediate a list of findings, logging progress."""
    kb = load_kb(kb_path) if kb_path else []
    if use_rag and kb_path and not kb:
        print(f"[remediator] warning: KB not found at {kb_path}, proceeding without RAG")
    remediated: list[RemediatedFinding] = []
    for i, f in enumerate(findings, 1):
        print(f"[remediator] ({i}/{len(findings)}) {f.id}")
        remediated.append(remediate(f, client, kb, use_rag=use_rag))
    return remediated
