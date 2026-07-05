"""Webapp tests: /models route + ensemble POST /runs/new + local-only reorder."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from vulntriage.webapp import runs as runs_mod
from vulntriage.webapp.app import app

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _wait_for(client, run_id, *, terminal=("done", "failed"), timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/runs/{run_id}/status")
        if r.status_code == 200 and r.json().get("state") in terminal:
            return r.json()
        time.sleep(0.05)
    raise AssertionError(f"run {run_id} did not reach {terminal} in {timeout}s")


@pytest.fixture
def client():
    runs_mod.registry._runs.clear()
    with (
        patch.object(runs_mod, "RUNS_ROOT", Path("/tmp/vt-test-runs")),
        patch.object(runs_mod, "EVAL_ROOT", Path("/tmp/vt-test-eval")),
    ):
        runs_mod.RUNS_ROOT.mkdir(parents=True, exist_ok=True)
        runs_mod.EVAL_ROOT.mkdir(parents=True, exist_ok=True)
        with TestClient(app) as c:
            yield c


def test_models_route_returns_list(client):
    with patch("vulntriage.webapp.app.list_models", return_value=["qwen3.5-4b", "llama3.1"]):
        r = client.get("/models", params={"provider": "lmstudio"})
    assert r.status_code == 200
    body = r.json()
    assert body["error"] is None
    assert "qwen3.5-4b" in body["models"]


def test_models_route_unknown_provider(client):
    r = client.get("/models", params={"provider": "nope"})
    assert r.status_code == 200
    body = r.json()
    assert body["models"] == []
    assert "unknown" in body["error"]


def test_models_route_best_effort_on_exception(client):
    with patch("vulntriage.webapp.app.list_models", side_effect=RuntimeError("boom")):
        r = client.get("/models", params={"provider": "lmstudio"})
    assert r.status_code == 200
    assert r.json()["models"] == []
    assert "boom" in r.json()["error"]


def _fake_run_pipeline(findings, client_, *, out_dir, **kwargs):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text("<html><body>STUB</body></html>")
    (out / "report.pdf").write_bytes(b"%PDF-1.4 stub")
    from vulntriage.pipeline import RunResult

    class _F:
        exploitability = type("E", (), {"value": "High"})()
        ensemble_unresolved = False

    return RunResult(
        run_dir=out,
        enriched=[],
        scored=[],
        prioritized=[_F() for _ in findings],
        remediated=[],
        written={"html": str(out / "report.html"), "pdf": str(out / "report.pdf")},
    )


def test_run_new_form_has_local_only_above_provider(client):
    r = client.get("/runs/new")
    assert r.status_code == 200
    text = r.text
    # Local-only checkbox must appear before the provider <select>.
    li = text.find('id="local_only"')
    prov = text.find('name="provider"')
    assert li != -1 and prov != -1
    assert li < prov, "local-only checkbox should render above the provider select"
    # Model datalist present.
    assert 'id="models-dl"' in text
    # Ensemble toggle present.
    assert 'id="ensemble_toggle"' in text


def test_ensemble_post_with_extra_models_reaches_done(client):
    with (
        patch("vulntriage.webapp.runs.make_client", lambda *a, **k: object()),
        patch("vulntriage.webapp.runs.run_pipeline", _fake_run_pipeline),
    ):
        r = client.post(
            "/runs/new",
            data={
                "mode": "dataset",
                "use_sample": "1",
                "provider": "lmstudio",
                "model": "primary",
                "ensemble_provider": ["ollama", "lmstudio"],
                "ensemble_model": ["a", "b"],
                "quorum": "2",
                "prompt_strategy": "few-shot",
                "asset_registry": str(DATA_DIR / "assets.yaml"),
                "kb_path": str(DATA_DIR / "cve_kb.json"),
                "use_rag": "1",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    run_id = r.headers["location"].split("/")[-1]
    _wait_for(client, run_id)
    # The params should record the ensemble.
    rec = runs_mod.registry.get(run_id)
    assert rec is not None
    assert rec.params.get("ensemble") == [
        {"provider": "ollama", "model": "a"},
        {"provider": "lmstudio", "model": "b"},
    ]
    assert rec.params.get("quorum") == 2


def test_local_only_blocks_ensemble_cloud_member(client):
    r = client.post(
        "/runs/new",
        data={
            "mode": "dataset",
            "use_sample": "1",
            "provider": "lmstudio",
            "model": "primary",
            "ensemble_provider": ["openai"],
            "ensemble_model": ["gpt-4o-mini"],
            "local_only": "1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "openai" in r.text


def test_ensemble_mismatched_lengths_rejected(client):
    r = client.post(
        "/runs/new",
        data={
            "mode": "dataset",
            "use_sample": "1",
            "provider": "lmstudio",
            "model": "primary",
            "ensemble_provider": ["ollama", "lmstudio"],
            "ensemble_model": ["a"],
        },
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "same length" in r.text
