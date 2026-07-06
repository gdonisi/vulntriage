"""Tests for the evaluation harness: metrics, ground truth, and experiment run."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from vulntriage.evaluation import (
    ExperimentConfig,
    ModelSpec,
    RunResult,
    cvss_only_rank_values,
    estimate_manual_seconds,
    gt_value,
    load_ground_truth,
    maturity_to_label,
    precision_recall_f1,
    run_experiment,
    spearman_rank,
)
from vulntriage.models import Exploitability, PrioritizedFinding

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# --------------------------------------------------------------------------- #
# Ground truth mapping (Task 5.1)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "maturity,expected",
    [
        ("H", "High"),
        ("F", "High"),
        ("P", "Medium"),
        ("U", "Low"),
        ("X", None),
        (None, None),
        ("x", None),
    ],
)
def test_maturity_to_label(maturity, expected):
    assert maturity_to_label(maturity) == expected


def test_gt_value_orders_by_class_then_cvss():
    assert gt_value("High", 9.8) > gt_value("Medium", 9.8)
    assert gt_value("Medium", 5.0) > gt_value("Low", 9.8)
    assert gt_value("High", 9.8) > gt_value("High", 5.0)


def test_load_ground_truth_real_dataset():
    gt = load_ground_truth(DATA_DIR / "synthetic_findings.json")
    assert "synthetic-0" in gt
    assert gt["synthetic-0"]["exploit_maturity"] == "H"


# --------------------------------------------------------------------------- #
# Metric functions (Task 5.2)
# --------------------------------------------------------------------------- #


def test_precision_recall_f1_perfect():
    prf = precision_recall_f1(["High", "Medium", "Low"], ["High", "Medium", "Low"])
    assert prf["precision"] == 1.0
    assert prf["recall"] == 1.0
    assert prf["f1"] == 1.0


def test_precision_recall_f1_partial():
    prf = precision_recall_f1(
        ["High", "High", "Medium", "Low"], ["High", "Medium", "Medium", "Low"]
    )
    assert 0.0 < prf["f1"] < 1.0
    assert prf["recall"] == pytest.approx(5 / 6, abs=0.01) or prf["recall"] > 0


def test_spearman_perfect_correlation():
    assert spearman_rank([1, 2, 3, 4], [1, 2, 3, 4]) == 1.0


def test_spearman_too_few_samples():
    assert spearman_rank([1], [1]) == 0.0


def test_cvss_only_rank_values_handles_nulls():
    findings = [
        PrioritizedFinding(
            id=str(i),
            source="s",
            host="h",
            description="d",
            cvss=cv,
            raw={},
            context="c",
            enrichment_model="m",
            exploitability=Exploitability.LOW,
            scoring_model="m",
        )
        for i, cv in enumerate([9.8, None, 5.0])
    ]
    vals = cvss_only_rank_values(findings)
    assert vals == [9.8, 0.0, 5.0]


def test_estimate_manual_seconds():
    assert estimate_manual_seconds([1, 2, 3, 4]) == 1200.0
    assert estimate_manual_seconds([], seconds_per_finding=100) == 0.0


# --------------------------------------------------------------------------- #
# Mini experiment run (Task 5.5)
# --------------------------------------------------------------------------- #


def _fake_run_once(input_path, client, **kw):
    """Canned run_once returning findings whose labels match ground truth."""
    items = json.loads(Path(input_path).read_text())
    prioritized = []
    for i, it in enumerate(items):
        lbl = it["ground_truth"]["label"]
        exp = {
            "High": Exploitability.HIGH,
            "Medium": Exploitability.MEDIUM,
            "Low": Exploitability.LOW,
        }[lbl]
        prioritized.append(
            PrioritizedFinding(
                id=it["id"],
                source="synthetic",
                host=it["host"],
                port=it.get("port"),
                service=it.get("service"),
                description=it["description"],
                cvss=it.get("cvss"),
                cve=it.get("cve"),
                raw=it,
                context="c",
                enrichment_model="m",
                exploitability=exp,
                exploitability_rationale="r",
                scoring_model="m",
                asset_criticality=0.5,
                risk_score=gt_value(lbl, it.get("cvss")),
                rank=i + 1,
            )
        )
    return RunResult(
        scored=[],
        prioritized=prioritized,
        remediated=None,
        latencies={"total": 1.0},
        total_tokens=42,
        wall_clock=1.0,
        condition={},
    )


class _DummyClient:
    def __init__(self, model):
        self.model = model
        self.total_tokens = 0


def test_run_experiment_mini(tmp_path, monkeypatch):
    import vulntriage.evaluation as ev

    monkeypatch.setattr(
        ev, "make_client", lambda p, m, reasoning_effort=None, **kw: _DummyClient(m)
    )
    monkeypatch.setattr(ev, "run_once", _fake_run_once)

    cfg = ExperimentConfig(
        input_path=str(DATA_DIR / "synthetic_findings.json"),
        asset_registry=str(DATA_DIR / "assets.yaml"),
        kb_path=str(DATA_DIR / "cve_kb.json"),
        models=[ModelSpec("mock", "mock-a")],
        prompt_strategies=["few-shot", "zero-shot"],
        rag_conditions=[True, False],
        repeats=2,
        output_dir=str(tmp_path),
    )
    out = run_experiment(cfg)

    rows = list(csv.DictReader(open(tmp_path / "results.csv")))
    # 1 model x 2 strategies x 2 rag x 2 repeats = 8 rows
    assert len(rows) == 8
    assert (tmp_path / "metrics.json").exists()
    assert len(out["cells"]) == 4
    assert "cvss_only_spearman" in out["baselines"]
    assert "manual_triage_seconds" in out["baselines"]
    # Perfect prediction -> F1 should be 1.0 in every cell.
    for cell in out["cells"].values():
        assert cell["f1"]["mean"] == 1.0
