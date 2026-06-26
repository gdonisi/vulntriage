"""Risk Prioritizer.

Pure-logic module (no LLM). Combines CVSS, exploitability, and asset
criticality into a composite risk score and ranks findings.

    Risk Score = (CVSS × 0.5) + (Exploitability × 0.3) + (Asset × 0.2)

CVSS is normalized to 0-1 by dividing by 10. Missing CVSS defaults to 5.0.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import PrioritizedFinding, ScoredFinding

DEFAULT_CVSS = 5.0


def load_asset_registry(path: str | Path | None) -> dict[str, float]:
    """Load hostname -> criticality (0.0-1.0) from a YAML file.

    Returns an empty registry if no path is given.
    """
    if path is None:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text()) or {}
    return {str(k): float(v) for k, v in data.items()}


def prioritize(
    findings: list[ScoredFinding],
    assets: dict[str, float] | None = None,
) -> list[PrioritizedFinding]:
    """Assign composite risk scores and rank findings highest-first."""
    assets = assets or {}
    prioritized: list[PrioritizedFinding] = []
    for f in findings:
        cvss = f.cvss if f.cvss is not None else DEFAULT_CVSS
        cvss_norm = min(cvss, 10.0) / 10.0
        exp = f.exploitability.numeric()
        asset = assets.get(f.host, 0.5)
        risk = (cvss_norm * 0.5) + (exp * 0.3) + (asset * 0.2)
        prioritized.append(
            PrioritizedFinding(
                **f.model_dump(),
                asset_criticality=asset,
                risk_score=round(risk, 3),
            )
        )
    prioritized.sort(key=lambda p: p.risk_score, reverse=True)
    for rank, p in enumerate(prioritized, 1):
        p.rank = rank
    return prioritized
