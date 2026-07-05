"""Tests for the vulntriage webapp (FastAPI TestClient + a patched run_pipeline).

We don't hit a real LLM — `run_pipeline` is patched to write a report and
return immediately, while still exercising the route wiring, the run
registry, and the dossier rendering (including the Download PDF control).
"""

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
    """Poll /runs/<id>/status until the worker reaches a terminal state."""
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
    # Point run roots at a temp location so tests don't touch the real output/.
    with (
        patch.object(runs_mod, "RUNS_ROOT", Path("/tmp/vt-test-runs")),
        patch.object(runs_mod, "EVAL_ROOT", Path("/tmp/vt-test-eval")),
    ):
        runs_mod.RUNS_ROOT.mkdir(parents=True, exist_ok=True)
        runs_mod.EVAL_ROOT.mkdir(parents=True, exist_ok=True)
        with TestClient(app) as c:
            yield c


def test_dashboard_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Case files" in r.text
    assert "/runs/new" in r.text


def test_runs_new_form(client):
    r = client.get("/runs/new")
    assert r.status_code == 200
    assert "New triage run" in r.text
    assert "Provider" in r.text
    # Confirms the PDF-downloadable-by-design note: this is the form, not the
    # dossier, so we just assert control labels render.
    assert "File this run" in r.text


def _fake_run_pipeline(findings, client_, *, out_dir, **kwargs):
    """Pretend to run the pipeline: write a stub report.html + report.pdf."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text("<html><body>STUB REPORT</body></html>")
    (out / "report.pdf").write_bytes(b"%PDF-1.4 stub")
    # Return a minimal RunResult-shaped object.
    from vulntriage.pipeline import RunResult

    class _F:
        exploitability = type("E", (), {"value": "High"})()

    return RunResult(
        run_dir=out,
        enriched=[],
        scored=[],
        prioritized=[_F() for _ in findings],
        remediated=[],
        written={"html": str(out / "report.html"), "pdf": str(out / "report.pdf")},
    )


def test_new_run_with_sample_reaches_done(client):
    # Patches must stay active while the background worker runs, so the whole
    # poll-and-fetch sequence stays inside the `with`.
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
                "model": "mock",
                "prompt_strategy": "few-shot",
                "asset_registry": str(DATA_DIR / "assets.yaml"),
                "kb_path": str(DATA_DIR / "cve_kb.json"),
                "use_rag": "1",
            },
            follow_redirects=False,
        )
        assert r.status_code == 303
        run_url = r.headers["location"]
        assert run_url.startswith("/runs/")
        run_id = run_url.split("/")[-1]

        _wait_for(client, run_id)
        detail = client.get(run_url)
        # Download the PDF within the patched scope too.
        pdf = client.get(f"/runs/{run_id}/report.pdf")

    assert detail.status_code == 200
    assert run_id in detail.text
    assert "Reviewed" in detail.text  # stamp label

    # Download PDF control must be present on a done run.
    assert "Download PDF" in detail.text
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF")


def test_local_only_blocks_cloud_provider(client):
    r = client.post(
        "/runs/new",
        data={
            "mode": "dataset",
            "use_sample": "1",
            "provider": "openai",
            "model": "gpt-4o",
            "local_only": "1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "openai" in r.text


def test_eval_new_form(client):
    r = client.get("/eval/new")
    assert r.status_code == 200
    assert "New evaluation" in r.text


def test_eval_list(client):
    r = client.get("/eval")
    assert r.status_code == 200
    assert "Evaluation runs" in r.text


def test_upload_multi_input_files(client, tmp_path):
    # Upload two files; the patched pipeline doesn't read them, but the route
    # must accept the multipart form.
    a = DATA_DIR / "sample_nmap.xml"
    b = DATA_DIR / "sample_nuclei.jsonl"
    with (
        patch("vulntriage.webapp.runs.make_client", lambda *a, **k: object()),
        patch("vulntriage.webapp.runs.run_pipeline", _fake_run_pipeline),
    ):
        r = client.post(
            "/runs/new",
            data={
                "mode": "dataset",
                "provider": "lmstudio",
                "model": "mock",
                "prompt_strategy": "few-shot",
            },
            files=[
                ("files", ("a.xml", a.read_bytes(), "application/xml")),
                ("files", ("b.jsonl", b.read_bytes(), "application/jsonl")),
            ],
            follow_redirects=False,
        )
        assert r.status_code == 303
        run_id = r.headers["location"].split("/")[-1]
        _wait_for(client, run_id)
        detail = client.get(f"/runs/{run_id}")

    assert detail.status_code == 200
    assert "Reviewed" in detail.text
