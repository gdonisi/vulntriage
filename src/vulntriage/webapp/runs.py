"""In-memory run registry and background worker for triage / eval runs.

A "run" is just a timestamped directory under ``output/runs/`` (triage) or
``output/eval/`` (eval); the filesystem is the source of truth. This module
holds only in-flight runs in memory and recovers their state from disk on
startup so a server restart never hides a half-finished run.

Pipeline progress is captured by redirecting the worker's ``sys.stdout`` into
a small ring buffer — the same ``print()`` lines the CLI emits become the live
progress feed, with no instrumentation of the pipeline itself.
"""

from __future__ import annotations

import contextlib
import io
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..evaluation import run_experiment
from ..llm import make_client
from ..parser import parse
from ..pipeline import run_pipeline
from ..scanner import run_nuclei

RUNS_ROOT = Path("output/runs")
EVAL_ROOT = Path("output/eval")
MAX_PROGRESS_LINES = 400

# Run states.
PENDING = "pending"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
INTERRUPTED = "interrupted"


@dataclass
class RunRecord:
    """A live or on-disk run."""

    run_id: str
    kind: str  # "triage" | "eval"
    run_dir: Path
    state: str = PENDING
    started_at: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    progress: list[str] = field(default_factory=list)
    error: str | None = None
    # Triage only:
    counts: dict[str, int] = field(default_factory=dict)
    # Eval only:
    metrics_path: Path | None = None

    def to_status(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "kind": self.kind,
            "state": self.state,
            "started_at": self.started_at,
            "params": self.params,
            "progress": self.progress[-40:],
            "error": self.error,
            "counts": self.counts,
            "has_report_html": (self.run_dir / "report.html").exists(),
            "has_report_pdf": (self.run_dir / "report.pdf").exists(),
            "has_metrics": self.metrics_path.exists() if self.metrics_path else False,
        }


class _StdoutCapture(io.TextIOBase):
    """Per-thread stdout capturing lines into a run's progress buffer."""

    def __init__(self, record: RunRecord) -> None:
        self._record = record
        self._buf = ""

    def write(self, s: str) -> int:
        if not s:
            return 0
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line:
                self._record.progress.append(line)
                if len(self._record.progress) > MAX_PROGRESS_LINES:
                    del self._record.progress[:-MAX_PROGRESS_LINES]
        return len(s)

    def flush(self) -> None:  # noqa: D401
        pass


class RunRegistry:
    """Thread-safe registry of in-flight runs."""

    def __init__(self) -> None:
        self._runs: dict[str, RunRecord] = {}
        self._lock = threading.Lock()
        self._counter = 0

    def add(self, record: RunRecord) -> RunRecord:
        with self._lock:
            self._runs[record.run_id] = record
        return record

    def get(self, run_id: str) -> RunRecord | None:
        return self._runs.get(run_id)

    def all_runs(self) -> list[RunRecord]:
        return list(self._runs.values())

    def remove(self, run_id: str) -> None:
        with self._lock:
            self._runs.pop(run_id, None)


registry = RunRegistry()


def _new_run_id(kind: str, ts: str) -> str:
    """``<ts>-<6hex>`` so rapid clicks never collide."""
    import uuid

    suffix = uuid.uuid4().hex[:6]
    return f"{ts}-{suffix}"


# --------------------------------------------------------------------------- #
# Triage worker
# --------------------------------------------------------------------------- #


def start_triage(
    *,
    input_paths: list[str],
    provider: str,
    model: str,
    reasoning_effort: str | None,
    local_only: bool,
    remediate: bool,
    use_rag: bool,
    kb_path: str,
    prompt_strategy: str,
    asset_registry: str | None,
    save_intermediates: bool,
    ensemble: list[tuple[str, str]] | None = None,
    quorum: int | None = None,
) -> str:
    """Create a run record, spawn the worker, and return the run id."""
    from datetime import datetime

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_id = _new_run_id("triage", ts)
    run_dir = RUNS_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    params: dict[str, Any] = {
        "input_paths": input_paths,
        "provider": provider,
        "model": model,
        "reasoning_effort": reasoning_effort,
        "local_only": local_only,
        "remediate": remediate,
        "use_rag": use_rag,
        "kb_path": kb_path,
        "prompt_strategy": prompt_strategy,
        "asset_registry": asset_registry,
        "save_intermediates": save_intermediates,
    }
    if ensemble:
        params["ensemble"] = [{"provider": p, "model": m} for p, m in ensemble]
        params["quorum"] = quorum
    record = RunRecord(
        run_id=run_id,
        kind="triage",
        run_dir=run_dir,
        state=PENDING,
        started_at=ts,
        params=params,
    )
    registry.add(record)
    t = threading.Thread(
        target=_triage_worker, args=(record,), daemon=True, name=f"triage-{run_id}"
    )
    t.start()
    return run_id


def _build_scoring_clients(record: RunRecord, primary_client: Any) -> list[Any] | None:
    """Build the ensemble scoring client list from record.params, if any."""
    p = record.params
    ensemble = p.get("ensemble")
    if not ensemble:
        return None
    clients = [primary_client]
    for m in ensemble:
        clients.append(
            make_client(m["provider"], m["model"], reasoning_effort=p["reasoning_effort"])
        )
    return clients


def _counts_from(prioritized: list) -> dict[str, int]:
    return {
        "total": len(prioritized),
        "high": sum(1 for f in prioritized if f.exploitability.value == "High"),
        "medium": sum(1 for f in prioritized if f.exploitability.value == "Medium"),
        "low": sum(1 for f in prioritized if f.exploitability.value == "Low"),
        "unresolved": sum(1 for f in prioritized if getattr(f, "ensemble_unresolved", False)),
    }


def _triage_worker(record: RunRecord) -> None:
    record.state = RUNNING
    p = record.params
    try:
        client = make_client(p["provider"], p["model"], reasoning_effort=p["reasoning_effort"])
        scoring_clients = _build_scoring_clients(record, client)
        findings: list = []
        for ip in p["input_paths"]:
            parsed = parse(ip)
            findings.extend(parsed)
            print(f"[pipeline] parsed {len(parsed)} findings from {ip}")
        if not findings:
            print("[pipeline] no findings to process")
            record.state = DONE
            record.counts = {"total": 0}
            return

        with contextlib.redirect_stdout(_StdoutCapture(record)):
            result = run_pipeline(
                findings,
                client,
                out_dir=record.run_dir,
                # Webapp always renders both HTML (for the in-app iframe) and
                # PDF (for the download control), regardless of --remediate.
                output_format="both",
                remediate=p["remediate"],
                use_rag=p["use_rag"],
                kb_path=p["kb_path"],
                prompt_strategy=p["prompt_strategy"],
                asset_registry=p["asset_registry"],
                save_intermediates_flag=p["save_intermediates"],
                scoring_clients=scoring_clients,
                scoring_quorum=p.get("quorum"),
            )
        record.counts = _counts_from(result.prioritized)
        record.state = DONE
    except Exception as e:  # noqa: BLE001
        record.state = FAILED
        record.error = f"{type(e).__name__}: {e}"
        record.progress.append(f"[error] {record.error}")


def start_triage_scan(
    *,
    target: str,
    provider: str,
    model: str,
    reasoning_effort: str | None,
    local_only: bool,
    remediate: bool,
    use_rag: bool,
    kb_path: str,
    prompt_strategy: str,
    asset_registry: str | None,
    save_intermediates: bool,
    ensemble: list[tuple[str, str]] | None = None,
    quorum: int | None = None,
) -> str:
    """Run a nuclei scan against *target*, then continue straight into triage."""
    from datetime import datetime

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_id = _new_run_id("triage", ts)
    run_dir = RUNS_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    record = RunRecord(
        run_id=run_id,
        kind="triage",
        run_dir=run_dir,
        state=PENDING,
        started_at=ts,
        params={
            "scan_target": target,
            "provider": provider,
            "model": model,
            "reasoning_effort": reasoning_effort,
            "local_only": local_only,
            "remediate": remediate,
            "use_rag": use_rag,
            "kb_path": kb_path,
            "prompt_strategy": prompt_strategy,
            "asset_registry": asset_registry,
            "save_intermediates": save_intermediates,
        },
    )
    if ensemble:
        record.params["ensemble"] = [{"provider": pv, "model": ml} for pv, ml in ensemble]
        record.params["quorum"] = quorum
    registry.add(record)
    t = threading.Thread(
        target=_triage_scan_worker, args=(record,), daemon=True, name=f"scan-{run_id}"
    )
    t.start()
    return run_id


def _triage_scan_worker(record: RunRecord) -> None:
    record.state = RUNNING
    p = record.params
    try:
        with contextlib.redirect_stdout(_StdoutCapture(record)):
            # Stage 1: scan.
            out_path = record.run_dir / "nuclei_scan.jsonl"
            run_nuclei(p["scan_target"], out_path)
            print(f"[pipeline] nuclei scan output saved to {out_path}")
            findings = parse(str(out_path))
            if not findings:
                print("[pipeline] no findings to process")
                record.state = DONE
                record.counts = {"total": 0}
                return
            client = make_client(p["provider"], p["model"], reasoning_effort=p["reasoning_effort"])
            scoring_clients = _build_scoring_clients(record, client)
            result = run_pipeline(
                findings,
                client,
                out_dir=record.run_dir,
                # Always both so the PDF is downloadable from the dossier.
                output_format="both",
                remediate=p["remediate"],
                use_rag=p["use_rag"],
                kb_path=p["kb_path"],
                prompt_strategy=p["prompt_strategy"],
                asset_registry=p["asset_registry"],
                save_intermediates_flag=p["save_intermediates"],
                scoring_clients=scoring_clients,
                scoring_quorum=p.get("quorum"),
            )
        record.counts = _counts_from(result.prioritized)
        record.state = DONE
    except Exception as e:  # noqa: BLE001
        record.state = FAILED
        record.error = f"{type(e).__name__}: {e}"
        record.progress.append(f"[error] {record.error}")


# --------------------------------------------------------------------------- #
# Eval worker
# --------------------------------------------------------------------------- #


def start_eval(
    *,
    input_path: str,
    provider: str,
    model: str,
    repeats: int,
    local_only: bool,
) -> str:
    from datetime import datetime

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_id = _new_run_id("eval", ts)
    run_dir = EVAL_ROOT / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    record = RunRecord(
        run_id=run_id,
        kind="eval",
        run_dir=run_dir,
        state=PENDING,
        started_at=ts,
        params={
            "input_path": input_path,
            "provider": provider,
            "model": model,
            "repeats": repeats,
            "local_only": local_only,
        },
        metrics_path=run_dir / "metrics.json",
    )
    registry.add(record)
    t = threading.Thread(target=_eval_worker, args=(record,), daemon=True, name=f"eval-{run_id}")
    t.start()
    return run_id


def _eval_worker(record: RunRecord) -> None:
    record.state = RUNNING
    p = record.params
    try:
        from ..evaluation import ExperimentConfig, ModelSpec

        config = ExperimentConfig(
            input_path=p["input_path"],
            models=[ModelSpec(p["provider"], p["model"])],
            prompt_strategies=["few-shot", "zero-shot"],
            rag_conditions=[True, False],
            repeats=p["repeats"],
            output_dir=str(record.run_dir),
        )
        with contextlib.redirect_stdout(_StdoutCapture(record)):
            run_experiment(config)
        record.state = DONE
    except Exception as e:  # noqa: BLE001
        record.state = FAILED
        record.error = f"{type(e).__name__}: {e}"
        record.progress.append(f"[error] {record.error}")


# --------------------------------------------------------------------------- #
# Disk discovery + recovery
# --------------------------------------------------------------------------- #


def list_run_dirs() -> list[Path]:
    """List triage run directories, newest first."""
    if not RUNS_ROOT.exists():
        return []
    return sorted(
        (d for d in RUNS_ROOT.iterdir() if d.is_dir()),
        key=lambda d: d.name,
        reverse=True,
    )


def list_eval_dirs() -> list[Path]:
    if not EVAL_ROOT.exists():
        return []
    return sorted(
        (d for d in EVAL_ROOT.iterdir() if d.is_dir()),
        key=lambda d: d.name,
        reverse=True,
    )


def recover_interrupted() -> None:
    """On startup, mark on-disk runs lacking a final artifact as interrupted."""
    for d in list_run_dirs():
        run_id = d.name
        if registry.get(run_id):
            continue  # live
        if not (d / "report.html").exists() and not (d / "report.pdf").exists():
            rec = RunRecord(
                run_id=run_id,
                kind="triage",
                run_dir=d,
                state=INTERRUPTED,
                started_at=run_id.split("-")[0],
            )
            registry.add(rec)
    for d in list_eval_dirs():
        run_id = d.name
        if registry.get(run_id):
            continue
        if not (d / "metrics.json").exists():
            rec = RunRecord(
                run_id=run_id,
                kind="eval",
                run_dir=d,
                state=INTERRUPTED,
                started_at=run_id.split("-")[0],
                metrics_path=d / "metrics.json",
            )
            registry.add(rec)


def record_from_disk(run_id: str, kind: str) -> RunRecord:
    """Build a read-only record for a past run from disk (not in the live registry)."""
    root = RUNS_ROOT if kind == "triage" else EVAL_ROOT
    d = root / run_id
    state = DONE
    if kind == "triage":
        if not (d / "report.html").exists() and not (d / "report.pdf").exists():
            state = INTERRUPTED
    else:
        if not (d / "metrics.json").exists():
            state = INTERRUPTED
    return RunRecord(
        run_id=run_id,
        kind=kind,
        run_dir=d,
        state=state,
        started_at=run_id.split("-")[0],
        metrics_path=(d / "metrics.json") if kind == "eval" else None,
    )
