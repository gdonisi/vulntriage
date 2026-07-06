"""Evaluation harness for the LLM-driven triage pipeline.

Runs the pipeline under a grid of experimental conditions (models x prompt
strategies x RAG on/off) and computes the metrics that answer the thesis
question:

  - accuracy  : precision / recall / F1 of LLM exploitability labels vs the
                CVSS exploit-maturity ground truth
  - ranking   : Spearman rank correlation of the pipeline's risk-score
                ordering vs the ground-truth ordering, compared against a
                CVSS-only baseline
  - throughput: pipeline wall-clock latency vs an estimated manual triage time

Outputs are written as ``metrics.json`` (per-cell aggregates with mean and
std) and ``results.csv`` (one row per cell-run with raw metrics), plus
baseline rows for CVSS-only ranking and manual triage.
"""

from __future__ import annotations

import csv
import json
import statistics
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from scipy.stats import spearmanr

from .enricher import enrich_all
from .llm import LLMClient, make_client
from .models import (
    PrioritizedFinding,
    RawFinding,
    RemediatedFinding,
    ScoredFinding,
)
from .parser import parse
from .prioritizer import load_asset_registry, prioritize
from .remediator import remediate_all
from .scorer import score_all

# CVSS temporal exploit-maturity (E) -> three-tier label, per the design spec.
_MATURITY_MAP: dict[str, str | None] = {
    "H": "High",
    "F": "High",
    "P": "Medium",
    "U": "Low",
    "X": None,
}

_LABEL_NUMERIC = {"High": 1.0, "Medium": 0.5, "Low": 0.1}

# Modelled manual triage time per finding (seconds). 5 minutes is a commonly
# cited order-of-magnitude estimate for a human analyst reviewing a raw
# scanner finding; override via the function argument.
DEFAULT_SECONDS_PER_FINDING = 300.0


# --------------------------------------------------------------------------- #
# Ground truth
# --------------------------------------------------------------------------- #


def load_ground_truth(path: str | Path) -> dict[str, dict]:
    """Load synthetic findings and index their ground-truth labels by finding id."""
    data = json.loads(Path(path).read_text())
    return {item["id"]: item.get("ground_truth", {}) for item in data}


def maturity_to_label(maturity: str | None) -> str | None:
    """Map a CVSS exploit-maturity value to a High/Medium/Low label.

    Returns ``None`` for ``"X"`` / unknown values (excluded from accuracy).
    """
    if not maturity:
        return None
    return _MATURITY_MAP.get(maturity.upper(), None)


def gt_value(label: str, cvss: float | None) -> float:
    """Ground-truth priority value used for ranking comparison.

    Higher = higher priority. The class dominates (multiplied by 100 so the
    gap between classes always exceeds the 0-10 CVSS range); CVSS breaks ties
    within a class.
    """
    return _LABEL_NUMERIC.get(label, 0.0) * 100.0 + (cvss or 0.0)


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


def precision_recall_f1(predicted: list[str], actual: list[str]) -> dict[str, float]:
    """Macro-averaged precision / recall / F1 over {High, Medium, Low}.

    Lists must be aligned and of equal length. Only findings with a non-None
    actual label should be passed in (callers filter X out beforehand).
    """
    classes = ["High", "Medium", "Low"]
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []
    for cls in classes:
        tp = sum(1 for p, a in zip(predicted, actual, strict=True) if p == cls and a == cls)
        fp = sum(1 for p, a in zip(predicted, actual, strict=True) if p == cls and a != cls)
        fn = sum(1 for p, a in zip(predicted, actual, strict=True) if p != cls and a == cls)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)
    return {
        "precision": statistics.mean(precisions) if precisions else 0.0,
        "recall": statistics.mean(recalls) if recalls else 0.0,
        "f1": statistics.mean(f1s) if f1s else 0.0,
    }


def spearman_rank(predicted_values: list[float], actual_values: list[float]) -> float:
    """Spearman rank correlation between predicted and ground-truth orderings.

    Returns 0.0 when there are fewer than two samples (Spearman undefined).
    """
    if len(predicted_values) < 2:
        return 0.0
    rho, _ = spearmanr(predicted_values, actual_values)
    if rho is None or (isinstance(rho, float) and rho != rho):  # NaN guard
        return 0.0
    return float(rho)


def cvss_only_rank_values(findings: Sequence[RawFinding]) -> list[float]:
    """CVSS-only baseline priority values (higher = higher priority).

    Findings with no CVSS are assigned 0 (sorted last).
    """
    return [f.cvss if f.cvss is not None else 0.0 for f in findings]


def estimate_manual_seconds(
    findings: list[Any], seconds_per_finding: float = DEFAULT_SECONDS_PER_FINDING
) -> float:
    """Modelled manual triage time for a list of findings."""
    return len(findings) * seconds_per_finding


# --------------------------------------------------------------------------- #
# Single run capture
# --------------------------------------------------------------------------- #


@dataclass
class RunResult:
    """Outputs and timings from a single pipeline run."""

    scored: list[ScoredFinding]
    prioritized: list[PrioritizedFinding]
    remediated: list[RemediatedFinding] | None
    latencies: dict[str, float] = field(default_factory=dict)
    total_tokens: int = 0
    wall_clock: float = 0.0
    condition: dict = field(default_factory=dict)


def run_once(
    input_path: str | Path,
    client: LLMClient,
    *,
    few_shot: bool = True,
    use_rag: bool = True,
    kb_path: str | Path | None = None,
    asset_registry: str | Path | None = None,
    remediate: bool = True,
) -> RunResult:
    """Run the full pipeline once and capture per-module latencies and tokens."""
    findings = parse(input_path)
    assets = load_asset_registry(asset_registry)
    latencies: dict[str, float] = {}

    wall_start = time.perf_counter()

    t = time.perf_counter()
    enriched = enrich_all(findings, client)
    latencies["enrich"] = time.perf_counter() - t

    t = time.perf_counter()
    scored = score_all(enriched, client, few_shot=few_shot)
    latencies["score"] = time.perf_counter() - t

    t = time.perf_counter()
    prioritized = prioritize(scored, assets)
    latencies["prioritize"] = time.perf_counter() - t

    remediated: list[RemediatedFinding] | None = None
    if remediate:
        t = time.perf_counter()
        remediated = remediate_all(prioritized, client, kb_path=kb_path, use_rag=use_rag)
        latencies["remediate"] = time.perf_counter() - t

    wall = time.perf_counter() - wall_start
    latencies["total"] = wall

    return RunResult(
        scored=scored,
        prioritized=prioritized,
        remediated=remediated,
        latencies=latencies,
        total_tokens=getattr(client, "total_tokens", 0),
        wall_clock=wall,
        condition={"few_shot": few_shot, "use_rag": use_rag},
    )


def compute_metrics(result: RunResult, ground_truth: dict[str, dict]) -> dict:
    """Compute the full metric set for a single run against ground truth."""
    prioritized = result.prioritized

    # Accuracy: only findings with a real maturity (not X).
    pred_labels: list[str] = []
    actual_labels: list[str] = []
    for f in prioritized:
        gt = ground_truth.get(f.id, {})
        maturity = gt.get("exploit_maturity")
        actual = maturity_to_label(maturity)
        if actual is None:
            continue
        pred_labels.append(f.exploitability.value)
        actual_labels.append(actual)
    prf = precision_recall_f1(pred_labels, actual_labels)

    # Ranking: correlate predicted risk scores with ground-truth priority values.
    pred_risk = [f.risk_score for f in prioritized]
    cvss_vals = cvss_only_rank_values(prioritized)
    gt_vals = [
        gt_value(ground_truth.get(f.id, {}).get("label", "Low"), f.cvss) for f in prioritized
    ]
    rho_pipeline = spearman_rank(pred_risk, gt_vals)
    rho_cvss = spearman_rank(cvss_vals, gt_vals)

    manual_seconds = estimate_manual_seconds(prioritized)

    return {
        "n_findings": len(prioritized),
        "n_accuracy": len(actual_labels),
        "precision": round(prf["precision"], 4),
        "recall": round(prf["recall"], 4),
        "f1": round(prf["f1"], 4),
        "spearman_pipeline": round(rho_pipeline, 4),
        "spearman_cvss_baseline": round(rho_cvss, 4),
        "pipeline_seconds": round(result.wall_clock, 3),
        "manual_seconds": manual_seconds,
        "throughput_ratio": round(manual_seconds / result.wall_clock, 2)
        if result.wall_clock
        else 0.0,
        "total_tokens": result.total_tokens,
        "latencies": {k: round(v, 3) for k, v in result.latencies.items()},
    }


# --------------------------------------------------------------------------- #
# Experiment runner
# --------------------------------------------------------------------------- #


@dataclass
class ModelSpec:
    provider: str
    model: str
    base_url: str | None = None
    api_key: str | None = None
    local: bool = False


@dataclass
class ExperimentConfig:
    input_path: str
    asset_registry: str | None = None
    kb_path: str | None = "data/cve_kb.json"
    models: list[ModelSpec] = field(default_factory=list)
    prompt_strategies: list[str] = field(default_factory=lambda: ["few-shot", "zero-shot"])
    rag_conditions: list[bool] = field(default_factory=lambda: [True, False])
    repeats: int = 3
    # ``None`` (default) => a timestamped ``output/eval/<ts>/`` dir is used per
    # run so previous results are never overwritten.
    output_dir: str | None = None


def _agg(values: list[float]) -> dict[str, float]:
    """Mean / std for a list of metric values."""
    if not values:
        return {"mean": 0.0, "std": 0.0}
    return {
        "mean": round(statistics.mean(values), 4),
        "std": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
    }


def run_experiment(config: ExperimentConfig) -> dict:
    """Run the full experiment grid and write metrics.json + results.csv."""
    from datetime import datetime

    ground_truth = load_ground_truth(config.input_path)
    out_dir = Path(config.output_dir or f"output/eval/{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)

    metric_keys = [
        "precision",
        "recall",
        "f1",
        "spearman_pipeline",
        "spearman_cvss_baseline",
        "pipeline_seconds",
        "manual_seconds",
        "throughput_ratio",
        "total_tokens",
    ]

    cells: dict[str, dict] = {}
    csv_rows: list[dict] = []

    for model_spec in config.models:
        for strategy in config.prompt_strategies:
            for use_rag in config.rag_conditions:
                model_name = f"{model_spec.provider}/{model_spec.model}"
                cell_name = f"{model_name}|{strategy}|rag={'on' if use_rag else 'off'}"
                print(f"\n[eval] cell: {cell_name}")
                run_metrics: dict[str, list[float]] = {k: [] for k in metric_keys}
                for rep in range(1, config.repeats + 1):
                    print(f"[eval]   run {rep}/{config.repeats}")
                    client = make_client(
                        model_spec.provider,
                        model_spec.model,
                        base_url=model_spec.base_url,
                        api_key=model_spec.api_key,
                        local=model_spec.local,
                    )
                    few_shot = strategy == "few-shot"
                    result = run_once(
                        config.input_path,
                        client,
                        few_shot=few_shot,
                        use_rag=use_rag,
                        kb_path=config.kb_path,
                        asset_registry=config.asset_registry,
                    )
                    metrics = compute_metrics(result, ground_truth)
                    metrics["model"] = f"{model_spec.provider}/{model_spec.model}"
                    metrics["prompt_strategy"] = strategy
                    metrics["rag"] = use_rag
                    metrics["run"] = rep
                    csv_rows.append(metrics)
                    for k in metric_keys:
                        run_metrics[k].append(metrics[k])

                cells[cell_name] = {k: _agg(v) for k, v in run_metrics.items()}
                cells[cell_name]["model"] = f"{model_spec.provider}/{model_spec.model}"
                cells[cell_name]["prompt_strategy"] = strategy
                cells[cell_name]["rag"] = use_rag

    # Baselines (computed once; they don't depend on the LLM).
    baseline_findings = parse(config.input_path)
    baseline_gt_vals = [
        gt_value(ground_truth.get(f.id, {}).get("label", "Low"), f.cvss) for f in baseline_findings
    ]
    baseline_cvss_vals = cvss_only_rank_values(baseline_findings)
    baselines = {
        "cvss_only_spearman": round(spearman_rank(baseline_cvss_vals, baseline_gt_vals), 4),
        "manual_triage_seconds": estimate_manual_seconds(baseline_findings),
    }

    output = {"cells": cells, "baselines": baselines, "config": _config_to_dict(config)}

    (out_dir / "metrics.json").write_text(json.dumps(output, indent=2))

    fieldnames = [
        "model",
        "prompt_strategy",
        "rag",
        "run",
        "n_findings",
        "n_accuracy",
        "precision",
        "recall",
        "f1",
        "spearman_pipeline",
        "spearman_cvss_baseline",
        "pipeline_seconds",
        "manual_seconds",
        "throughput_ratio",
        "total_tokens",
    ]
    with (out_dir / "results.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(csv_rows)

    print(f"\n[eval] wrote {out_dir / 'metrics.json'} and {out_dir / 'results.csv'}")
    return output


def _config_to_dict(config: ExperimentConfig) -> dict:
    return {
        "input_path": config.input_path,
        "asset_registry": config.asset_registry,
        "kb_path": config.kb_path,
        "models": [asdict(m) for m in config.models],
        "prompt_strategies": config.prompt_strategies,
        "rag_conditions": config.rag_conditions,
        "repeats": config.repeats,
        "output_dir": config.output_dir,
    }


def load_config(path: str | Path) -> ExperimentConfig:
    """Load an experiment config from a JSON file.

    Expected schema (all keys optional except models / input_path)::

        {
          "input_path": "data/synthetic_findings.json",
          "asset_registry": "data/assets.yaml",
          "kb_path": "data/cve_kb.json",
          "models": [{"provider": "lmstudio", "model": "qwen3.5-4b"}],
          "prompt_strategies": ["few-shot", "zero-shot"],
          "rag_conditions": [true, false],
          "repeats": 3,
          "output_dir": "output/eval"  // optional; null/omitted => output/eval/<timestamp>/
        }
    """
    data = json.loads(Path(path).read_text())
    models = [ModelSpec(**m) for m in data.get("models", [])]
    return ExperimentConfig(
        input_path=data["input_path"],
        asset_registry=data.get("asset_registry"),
        kb_path=data.get("kb_path", "data/cve_kb.json"),
        models=models,
        prompt_strategies=data.get("prompt_strategies", ["few-shot", "zero-shot"]),
        rag_conditions=data.get("rag_conditions", [True, False]),
        repeats=data.get("repeats", 3),
        output_dir=data.get("output_dir"),
    )
