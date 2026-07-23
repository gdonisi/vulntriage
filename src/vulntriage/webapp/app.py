"""FastAPI app: local web interface for the vulntriage pipeline.

Run with::

    uv run uvicorn vulntriage.webapp.app:app --reload
    # or
    uv run python main.py --web

Serves a "Case File" UI (see ``static/style.css`` and ``templates/``) over the
filesystem run layout under ``output/runs/`` and ``output/eval/``.
"""

from __future__ import annotations

import contextlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..llm import LOCAL_PROVIDERS, PROVIDER_LABELS, is_local_provider, list_models
from . import runs as runs_mod

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

DATA_DIR = BASE_DIR.parent.parent.parent / "data"
SAMPLE_INPUT = DATA_DIR / "synthetic_findings.json"
ASSET_REGISTRY_DEFAULT = "data/assets.yaml"
KB_DEFAULT = "data/cve_kb.json"

PROVIDERS = [
    "lmstudio",
    "ollama",
    "llamacpp",
    "vllm",
    "openai",
    "openrouter",
    "anthropic",
    "google",
    "deepseek",
    "custom",
]


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Create run dirs and recover interrupted on-disk runs on startup."""
    runs_mod.RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    runs_mod.EVAL_ROOT.mkdir(parents=True, exist_ok=True)
    runs_mod.recover_interrupted()
    yield


app = FastAPI(title="vulntriage", docs_url=None, redoc_url=None, lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def stamp_word(state: str) -> str:
    """Map a run state to the rubber-stamp label."""
    return {
        "pending": "Filed",
        "running": "In Review",
        "done": "Reviewed",
        "failed": "Failed",
        "interrupted": "Halted",
    }.get(state, state)


templates.env.globals["stamp_word"] = stamp_word


def _basename(path: str) -> str:
    from pathlib import Path

    return Path(path).name


templates.env.filters["basename"] = _basename


def _render(request: Request, name: str, **ctx: Any) -> HTMLResponse:
    """Render a template with the request bound (Starlette 1.x API)."""
    return templates.TemplateResponse(request, name, ctx)


def _providers_for_view(local_only: bool) -> list[dict[str, Any]]:
    return [
        {
            "name": p,
            "label": PROVIDER_LABELS.get(p, p),
            "local": is_local_provider(p),
        }
        for p in PROVIDERS
        # Custom is always visible; for others, filter by local_only.
        if p == "custom" or (not local_only or is_local_provider(p))
    ]


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    live = sorted(runs_mod.registry.all_runs(), key=lambda r: r.run_id, reverse=True)
    # Live in-memory runs are a mixed list (triage + eval); separate them by
    # kind so each section renders only its own runs and links resolve.
    live_triage = [r for r in live if r.kind == "triage"]
    live_eval = [r for r in live if r.kind == "eval"]
    triage_dirs = runs_mod.list_run_dirs()
    eval_dirs = runs_mod.list_eval_dirs()
    # Merge live and on-disk, preferring live records, per kind.
    seen_triage = {r.run_id for r in live_triage}
    seen_eval = {r.run_id for r in live_eval}
    on_disk: list[runs_mod.RunRecord] = []
    for d in triage_dirs:
        if d.name in seen_triage:
            continue
        on_disk.append(runs_mod.record_from_disk(d.name, "triage"))
    eval_on_disk: list[runs_mod.RunRecord] = []
    for d in eval_dirs:
        if d.name in seen_eval:
            continue
        eval_on_disk.append(runs_mod.record_from_disk(d.name, "eval"))
    return _render(
        request,
        "dashboard.html",
        triage_runs=live_triage + on_disk,
        eval_runs=live_eval + eval_on_disk,
        sample_available=SAMPLE_INPUT.exists(),
    )


# --------------------------------------------------------------------------- #
# Triage runs
# --------------------------------------------------------------------------- #


@app.get("/runs", response_class=HTMLResponse)
def runs_list(request: Request) -> HTMLResponse:
    all_live = sorted(runs_mod.registry.all_runs(), key=lambda r: r.run_id, reverse=True)
    # Only triage runs belong on the /runs page; live eval runs have no report
    # here and would link to a 404.
    live = [r for r in all_live if r.kind == "triage"]
    seen = {r.run_id for r in live}
    on_disk = [runs_mod.record_from_disk(d.name, "triage") for d in runs_mod.list_run_dirs()]
    on_disk = [r for r in on_disk if r.run_id not in seen]
    return _render(request, "runs_list.html", runs=live + on_disk)


@app.get("/runs/new", response_class=HTMLResponse)
def run_new_form(request: Request) -> HTMLResponse:
    return _render(
        request,
        "run_new.html",
        providers=_providers_for_view(local_only=False),
        local_providers=sorted(LOCAL_PROVIDERS),
        prompt_strategies=["few-shot", "zero-shot"],
        kb_default=KB_DEFAULT,
        asset_default=ASSET_REGISTRY_DEFAULT,
        sample_available=SAMPLE_INPUT.exists(),
    )


@app.get("/models", response_class=JSONResponse)
def models_for_provider(
    provider: str,
    base_url: str | None = None,
    api_key: str | None = None,
) -> JSONResponse:
    """Best-effort enumeration of a provider's models for the model picker.

    Returns ``{"models": [...], "error": null}``. If the provider is unknown,
    auth is missing, or the endpoint is unreachable, ``models`` is ``[]`` and
    ``error`` carries a short message so the client can fall back to free text.

    For ``custom`` providers, *base_url* and *api_key* are forwarded to
    ``list_models`` so the model picker reaches the correct endpoint.
    """
    if provider not in PROVIDERS and provider != "custom":
        return JSONResponse({"models": [], "error": f"unknown provider: {provider}"})
    try:
        models = list_models(provider, base_url=base_url, api_key=api_key)
    except Exception as e:  # noqa: BLE001 — best-effort; never block the form
        return JSONResponse({"models": [], "error": str(e)})
    return JSONResponse({"models": models, "error": None})


@app.post("/runs/new")
async def run_new_submit(
    mode: str = Form("dataset"),
    files: list[UploadFile] = File(default_factory=list),  # noqa: B008
    use_sample: bool = Form(False),
    scan_target: str = Form(""),
    provider: str = Form(...),
    model: str = Form(...),
    reasoning_effort: str = Form(""),
    local_only: bool = Form(False),
    remediate: bool = Form(False),
    use_rag: bool = Form(True),
    kb_path: str = Form(KB_DEFAULT),
    prompt_strategy: str = Form("few-shot"),
    asset_registry: str = Form(""),
    save_intermediates: bool = Form(False),
    # Custom provider fields.
    custom_base_url: str = Form(""),
    api_key: str = Form(""),
    custom_local: bool = Form(False),
    # Ensemble (optional): repeated provider/model pairs + a quorum.
    ensemble_provider: list[str] = Form(default_factory=list),  # noqa: B008
    ensemble_model: list[str] = Form(default_factory=list),  # noqa: B008
    ensemble_base_url: list[str] = Form(default_factory=list),  # noqa: B008
    ensemble_local: list[str] = Form(default_factory=list),  # noqa: B008
    quorum: int | None = Form(None),
) -> RedirectResponse:
    _validate_provider(provider, local_only, custom_local=custom_local)

    # Validate custom provider args before any work.
    if provider == "custom" and not custom_base_url.strip():
        raise HTTPException(
            status_code=400, detail="Base URL is required for custom providers."
        )

    # Validate + normalize the ensemble. The primary (provider, model) is the
    # first ensemble member; the extras are zipped from the repeated fields.
    ensemble: list[dict[str, object]] | None = None
    if ensemble_provider or ensemble_model:
        if len(ensemble_provider) != len(ensemble_model):
            raise HTTPException(
                status_code=400,
                detail="ensemble_provider and ensemble_model must be the same length",
            )
        members: list[dict[str, object]] = []
        for i, (prov, mdl) in enumerate(zip(ensemble_provider, ensemble_model, strict=False)):
            if not mdl.strip():
                raise HTTPException(status_code=400, detail="ensemble model must not be empty")
            base = ensemble_base_url[i] if i < len(ensemble_base_url) else ""
            loc = ensemble_local[i] if i < len(ensemble_local) else ""
            _validate_provider(prov, local_only, custom_local=(loc == "1"))
            if prov == "custom" and not base.strip():
                raise HTTPException(
                    status_code=400,
                    detail=f"Base URL is required for custom ensemble member #{i + 1}.",
                )
            members.append({
                "provider": prov,
                "model": mdl,
                "base_url": base.strip() or None,
                "local": loc == "1",
            })
        ensemble = members

    reasoning = reasoning_effort or None
    asset = asset_registry or None

    if mode == "scan":
        if not scan_target:
            raise HTTPException(status_code=400, detail="Scan mode requires a target.")
        run_id = runs_mod.start_triage_scan(
            target=scan_target,
            provider=provider,
            model=model,
            reasoning_effort=reasoning,
            local_only=local_only,
            remediate=remediate,
            use_rag=use_rag,
            kb_path=kb_path,
            prompt_strategy=prompt_strategy,
            asset_registry=asset,
            save_intermediates=save_intermediates,
            ensemble=ensemble,
            quorum=quorum,
            custom_base_url=custom_base_url.strip() or None,
            api_key=api_key.strip() or None,
            custom_local=custom_local,
        )
        return RedirectResponse(url=f"/runs/{run_id}", status_code=303)

    # dataset mode: uploads or sample.
    input_paths: list[str] = []
    run_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    # Precompute the run id so uploaded files land *inside* the real run dir
    # ("output/runs/<ts>-<hex>/..."), which start_triage will reuse. Saving
    # them under the bare "<ts>" dir left a ghost interrupted entry (no report
    # ever appeared there) on every upload-based run.
    run_id = runs_mod._new_run_id("triage", run_ts)
    for i, uf in enumerate(files):
        if not uf.filename:
            continue
        saved = runs_mod.RUNS_ROOT / run_id / f"upload_{i}_{uf.filename}"
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(await uf.read())
        input_paths.append(str(saved))
    if use_sample and SAMPLE_INPUT.exists():
        input_paths.insert(0, str(SAMPLE_INPUT))
    if not input_paths:
        # Clean the empty upload dir.
        d = runs_mod.RUNS_ROOT / run_id
        if d.exists() and not any(d.iterdir()):
            d.rmdir()
        raise HTTPException(status_code=400, detail="Provide at least one input file.")
    run_id = runs_mod.start_triage(
        input_paths=input_paths,
        provider=provider,
        model=model,
        reasoning_effort=reasoning,
        local_only=local_only,
        remediate=remediate,
        use_rag=use_rag,
        kb_path=kb_path,
        prompt_strategy=prompt_strategy,
        asset_registry=asset,
        save_intermediates=save_intermediates,
        ensemble=ensemble,
        quorum=quorum,
        custom_base_url=custom_base_url.strip() or None,
        api_key=api_key.strip() or None,
        custom_local=custom_local,
        run_id=run_id,
    )
    return RedirectResponse(url=f"/runs/{run_id}", status_code=303)


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: str) -> HTMLResponse:
    record = runs_mod.registry.get(run_id) or runs_mod.record_from_disk(run_id, "triage")
    if not record.run_dir.exists():
        raise HTTPException(status_code=404, detail="Run not found.")
    return _render(request, "run_detail.html", record=record)


@app.get("/runs/{run_id}/status")
def run_status(run_id: str) -> JSONResponse:
    record = _live_or_disk(run_id, "triage")
    return JSONResponse(record.to_status())


@app.get("/runs/{run_id}/report.html", response_class=HTMLResponse)
def run_report_html(run_id: str) -> HTMLResponse:
    record = _live_or_disk(run_id, "triage")
    path = record.run_dir / "report.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not yet generated.")
    return HTMLResponse(path.read_text())


@app.get("/runs/{run_id}/report.pdf")
def run_report_pdf(run_id: str) -> FileResponse:
    """Download the PDF report (browser Save dialog)."""
    record = _live_or_disk(run_id, "triage")
    path = record.run_dir / "report.pdf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="PDF report not yet generated.")
    return FileResponse(
        str(path),
        media_type="application/pdf",
        filename=f"vulntriage-{run_id}.pdf",
    )


@app.get("/runs/{run_id}/download")
def run_download(run_id: str) -> Any:
    """Zip the intermediates dir for download."""
    import io
    import zipfile

    record = _live_or_disk(run_id, "triage")
    inter = record.run_dir / "intermediates"
    if not inter.exists():
        raise HTTPException(status_code=404, detail="No intermediates for this run.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in inter.iterdir():
            if p.is_file():
                zf.write(p, arcname=p.name)
    buf.seek(0)
    # FileResponse expects a *file path* and calls os.stat() on it; passing a
    # BytesIO raises TypeError -> 500 on every download. Return the in-memory
    # bytes directly with an explicit Content-Disposition instead.
    return Response(
        buf.getvalue(),
        media_type="application/zip",
        headers={
            "content-disposition": (
                f'attachment; filename="vulntriage-{run_id}-intermediates.zip"'
            )
        },
    )


# --------------------------------------------------------------------------- #
# Eval runs
# --------------------------------------------------------------------------- #


@app.get("/eval", response_class=HTMLResponse)
def eval_list(request: Request) -> HTMLResponse:
    live = [r for r in runs_mod.registry.all_runs() if r.kind == "eval"]
    seen = {r.run_id for r in live}
    on_disk = [runs_mod.record_from_disk(d.name, "eval") for d in runs_mod.list_eval_dirs()]
    on_disk = [r for r in on_disk if r.run_id not in seen]
    return _render(request, "eval_list.html", runs=live + on_disk)


@app.get("/eval/new", response_class=HTMLResponse)
def eval_new_form(request: Request) -> HTMLResponse:
    return _render(
        request,
        "eval_new.html",
        providers=_providers_for_view(local_only=False),
        local_providers=sorted(LOCAL_PROVIDERS),
        sample_available=SAMPLE_INPUT.exists(),
    )


@app.post("/eval/new")
def eval_new_submit(
    input_path: str = Form(...),
    provider: str = Form(...),
    model: str = Form(...),
    repeats: int = Form(3),
    local_only: bool = Form(False),
    custom_base_url: str = Form(""),
    api_key: str = Form(""),
    custom_local: bool = Form(False),
) -> RedirectResponse:
    _validate_provider(provider, local_only, custom_local=custom_local)
    if provider == "custom" and not custom_base_url.strip():
        raise HTTPException(
            status_code=400, detail="Base URL is required for custom providers."
        )
    if not Path(input_path).exists():
        raise HTTPException(status_code=400, detail=f"Input dataset not found: {input_path}")
    run_id = runs_mod.start_eval(
        input_path=input_path,
        provider=provider,
        model=model,
        repeats=repeats,
        local_only=local_only,
        custom_base_url=custom_base_url.strip() or None,
        api_key=api_key.strip() or None,
        custom_local=custom_local,
    )
    return RedirectResponse(url=f"/eval/{run_id}", status_code=303)


@app.get("/eval/{run_id}", response_class=HTMLResponse)
def eval_detail(request: Request, run_id: str) -> HTMLResponse:
    record = runs_mod.registry.get(run_id) or runs_mod.record_from_disk(run_id, "eval")
    if not record.run_dir.exists():
        raise HTTPException(status_code=404, detail="Eval run not found.")
    metrics: dict[str, Any] = {}
    if record.metrics_path and record.metrics_path.exists():
        metrics = json.loads(record.metrics_path.read_text())
    return _render(request, "eval_detail.html", record=record, metrics=metrics)


@app.get("/eval/{run_id}/metrics")
def eval_metrics(run_id: str) -> FileResponse:
    record = runs_mod.registry.get(run_id) or runs_mod.record_from_disk(run_id, "eval")
    p = record.run_dir / "metrics.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="metrics.json not yet generated.")
    return FileResponse(str(p), media_type="application/json", filename=p.name)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _validate_provider(provider: str, local_only: bool, *, custom_local: bool = False) -> None:
    if provider not in PROVIDERS and provider != "custom":
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    if not local_only:
        return
    # A custom provider is accepted under local-only only when the caller
    # marked it self-hosted (the "Self-hosted (local)" checkbox / --local),
    # mirroring the CLI. Built-in providers are gated by the hardcoded local set.
    if provider == "custom":
        if not custom_local:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Local-only mode requires a self-hosted custom provider: "
                    "tick the \"Self-hosted (local)\" box (or use a local backend)."
                ),
            )
    elif not is_local_provider(provider):
        raise HTTPException(
            status_code=400,
            detail=(
                f"--local-only is set but cloud provider requested: {provider}. "
                f"Allowed: {', '.join(sorted(LOCAL_PROVIDERS))} "
                f"(or use --provider custom --local)."
            ),
        )


def _live_or_disk(run_id: str, kind: str) -> runs_mod.RunRecord:
    rec = runs_mod.registry.get(run_id)
    if rec is None:
        rec = runs_mod.record_from_disk(run_id, kind)
    return rec


def run() -> int:
    """Entry point for the ``vulntriage-web`` script."""
    import uvicorn

    uvicorn.run("vulntriage.webapp.app:app", host="127.0.0.1", port=9000, log_level="info")
    return 0
