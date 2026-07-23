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


def _strict_majority(
    votes: dict[str, str],
    quorum: int | None,
) -> tuple[Exploitability, str, bool]:
    """Merge *votes* (``model_name -> label``) by strict-majority quorum.

    Returns ``(exploitability, rationale, unresolved)``.

    - If ``quorum`` is None it defaults to ``floor(N/2) + 1`` (a genuine
      majority; for even N this requires unanimity, for odd N a bare majority).
    - If any single label reaches the quorum, that label wins and
      ``unresolved`` is False.
    - If no label reaches the quorum, ``unresolved`` is True and the
      exploitability is set to the *highest* tally label (so the
      deterministic prioritizer still ranks the finding somewhere sane).
    - The rationale is a fully transparent vote summary, e.g.
      ``"2/3 models: High=2, Medium=1 (quorum 2 -> High)"``.
    """
    n = len(votes)
    k = quorum if quorum is not None else (n // 2 + 1)
    tally: dict[str, int] = {}
    for label in votes.values():
        tally[label] = tally.get(label, 0) + 1
    # Highest tally wins; break ties by severity (High > Medium > Low) so the
    # fallback is deterministic rather than dict-insertion order.
    _severity = {"High": 3, "Medium": 2, "Low": 1}
    winner_label = "Low"
    winner_count = 0
    for label, count in tally.items():
        if count > winner_count or (
            count == winner_count
            and _severity.get(label, 0) > _severity.get(winner_label, 0)
        ):
            winner_label = label
            winner_count = count
    # votes come from Exploitability.value, so they are already canonical.
    _by_name = {e.value: e for e in Exploitability}
    exploitability = _by_name.get(winner_label, Exploitability.LOW)
    resolved = winner_count >= k
    summary = ", ".join(f"{lbl}={cnt}" for lbl, cnt in sorted(tally.items()))
    decision = winner_label if resolved else f"unresolved -> fallback {winner_label}"
    # Report the actual highest tally even when unresolved (the "0/N" form
    # was misleading — the tallies are the real information).
    rationale = f"{winner_count}/{n} models: {summary} (quorum {k} -> {decision})"
    return exploitability, rationale, not resolved


def score_all(
    findings: list[EnrichedFinding],
    client: LLMClient,
    *,
    few_shot: bool = True,
    clients: list[LLMClient] | None = None,
    quorum: int | None = None,
) -> list[ScoredFinding]:
    """Score a list of findings, logging progress.

    Single-model path (``clients is None``, the default): each finding is
    scored once with *client* — exactly the historical behaviour.

    Ensemble path (``clients`` is a non-empty list): each finding is scored
    once per client; the resulting High/Medium/Low votes are merged by
    strict-majority quorum (:func:`_strict_majority`) to reduce false
    positives. ``client`` is used as the primary (first ensemble member);
    it should appear in ``clients`` already. Enrichment and remediation are
    not fanned out — only scoring is.
    """
    ensemble = bool(clients)
    scored: list[ScoredFinding] = []
    for i, f in enumerate(findings, 1):
        print(f"[scorer] ({i}/{len(findings)}) {f.id}")
        if not ensemble:
            scored.append(score(f, client, few_shot=few_shot))
            continue
        votes: dict[str, str] = {}
        # Key by model name, but disambiguate duplicates (e.g. the primary
        # repeated in --ensemble, or the same model id via two providers) so
        # votes never collapse — the quorum is computed on the real N.
        seen_counts: dict[str, int] = {}
        for c in clients or []:
            s = score(f, c, few_shot=few_shot)
            base = c.model
            seen_counts[base] = seen_counts.get(base, 0) + 1
            key = base if seen_counts[base] == 1 else f"{base}#{seen_counts[base]}"
            votes[key] = s.exploitability.value
        exploitability, rationale, unresolved = _strict_majority(votes, quorum)
        scored.append(
            ScoredFinding(
                **f.model_dump(),
                exploitability=exploitability,
                exploitability_rationale=rationale,
                scoring_model=client.model,
                exploitability_votes=votes,
                ensemble_quorum=quorum if quorum is not None else (len(votes) // 2 + 1),
                ensemble_unresolved=unresolved,
            )
        )
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
