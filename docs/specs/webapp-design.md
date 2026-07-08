# Design: vulntriage Webapp

## Goal

A local-first web interface for the existing triage pipeline so the thesis
tool can be driven from a browser: start a triage run (or an eval grid),
watch it progress, and read the resulting report in-context. The CLI stays
the canonical entry point; the webapp is a thin viewer/controller on top of
the same `output/runs/<ts>/` and `output/eval/<ts>/` layout — no separate
database, no separate run model.

## Audience & job

The single reader is the thesis author (and, during the defense, a committee
member glancing at the screen). The page's job is to make one run legible at
a time: what was triaged, with which model, what came out, and what each
finding was rated — without leaving the browser.

## Assumptions

1. **Local-only deployment.** The app runs on `127.0.0.1:9000` via `uv run
   uvicorn`. No auth, no HTTPS, no production hardening — it's a research
   instrument.
2. **The CLI is the source of truth for run layout.** A "run" is exactly a
   timestamped directory under `output/runs/` (or `output/eval/`). The
   webapp lists dirs on disk and reads the files the pipeline already
   writes (`report.html`, `report.pdf`, `intermediates/*.json`). It does not
   invent a parallel state store.
3. **LLM calls are synchronous and slow.** The openai SDK is sync, so each
   run executes in a background thread; the browser polls a status JSON
   endpoint. In-memory run registry holds live status; on restart, in-flight
   runs are recovered as "interrupted" by scanning the dir.
4. **No new heavy deps.** Add `fastapi` + `uvicorn` + `python-multipart`
   (for uploads). Jinja2 is already present.
5. **The existing `report.html` template is reused as-is** for the rendered
   report; it is shown in an `<iframe>` from the run page so the standalone
   file and the in-app view are byte-identical.
6. **Provider/model options mirror the CLI exactly** — same `make_client`
   factory, same `LOCAL_PROVIDERS` gate (the `--local-only` checkbox).
7. **Nuclei scan-from-web is allowed** because the operator is authorized on
   their own lab; it reuses `run_nuclei` and then continues into triage in
   the same background worker, exactly like `--scan nuclei …`.

## Unknowns / Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Long LLM runs block the worker thread; UI must feel alive | Medium | Polling status with live log tail (last N progress lines) every ~1s; status JSON is cheap |
| Run interrupted by server restart leaves a half-written dir | Low | On boot, scan `output/runs/*`; any dir without `report.html` (and not in the live registry) is marked "interrupted"; user can re-run |
| Upload of large scanner files | Low | Multipart upload to a temp file under the run dir; size is bounded by FastAPI's default; fine for Nmap XML / Nuclei JSONL |
| Eval grid (36 runs) takes many minutes; browser tab may close | Medium | Eval runs in a thread; the `output/eval/<ts>/` dir is the durable record; the webapp only needs to show "running/done" |
| Concurrent runs colliding on the same timestamp | Low | Run id is `<ts>-<6hex>`; the CLI's `_timestamp()` gains no suffix, the webapp appends a short uuid to guarantee uniqueness across rapid clicks |
| Re-running the pipeline from a web worker duplicates `print()` noise in console | Low | Redirect stdout per-worker into a log buffer that doubles as the progress feed |

## Proposed Approach

### Architecture

```
FastAPI app (uvicorn, 127.0.0.1:9000)
  ├── GET  /                    dashboard: recent runs + eval runs + "New run" CTA
  ├── GET  /runs                list of triage runs (file-browser of output/runs/)
  ├── GET  /runs/new            intake form (pre-printed-form styled)
  ├── POST /runs/new            create run id, spawn worker, redirect to /runs/<id>
  ├── GET  /runs/<id>           run dossier: stamped manifest + live progress + report
  ├── GET  /runs/<id>/status    JSON: state, progress lines, counts (polled)
  ├── GET  /runs/<id>/report.*  serve report.html / report.pdf from disk
  ├── GET  /runs/<id>/download  intermediates/*.json as downloads
  ├── GET  /eval                list of eval runs (output/eval/)
  ├── GET  /eval/new            eval intake form (provider/model or config upload)
  ├── POST /eval/new            spawn eval worker, redirect to /eval/<id>
  ├── GET  /eval/<id>           eval dossier: status + metrics.json rendered as a table
  └── GET  /eval/<id>/metrics   raw metrics.json
```

### Run worker

A `RunWorker` thread runs the same call sequence the CLI uses today
(`parse → enrich_all → score_all → prioritize → remediate_all → compose`),
capturing each `print()` into a `progress: list[str]` (via a contextmanager
that redirects `sys.stdout` per-thread) and writing outputs to
`output/runs/<id>/`. State machine: `pending → running → done | failed |
interrupted`. The worker is the **only** writer to the run dir.

### Reused library surface

- `vulntriage.cli` logic is partly refactored: the pipeline body of
  `cli.main` (steps 2–9) is extracted into a `run_pipeline(input_paths,
  client, *, remediate, use_rag, kb_path, prompt_strategy,
  asset_registry, out_dir, save_intermediates) -> dict` function in a new
  `src/vulntriage/pipeline.py`. The CLI calls it; the webapp calls it. No
  behaviour change to the CLI.
- `compose_report`, `run_nuclei`, `make_client`, `LOCAL_PROVIDERS`,
  `load_asset_registry`, `run_experiment` are all imported as-is.

### Files

```
src/vulntriage/
  pipeline.py          # NEW: extracted triage run logic (CLI + webapp share it)
src/webapp/
  __init__.py
  app.py              # FastAPI app, routes, run registry, worker spawning
  runs.py             # in-memory RunRegistry, RunWorker thread, stdout capture
  templates/          # Jinja2 page templates (NOT the report — that's data/templates)
    base.html
    dashboard.html
    runs_list.html
    run_new.html
    run_detail.html
    eval_list.html
    eval_new.html
    eval_detail.html
    partials/
      manifest.html
      progress.html
      stamped.html
  static/
    style.css          # the "Case File" design system (tokens below)
    app.js            # tiny: polling status, no framework
docker/webapp/
  Dockerfile          # local-only image (optional)
tests/
  test_pipeline.py    # run_pipeline() unit test with mock client
  test_webapp.py      # TestClient: dashboard, new run -> done, eval list
pyproject.toml         # +fastapi, +uvicorn, +python-multipart
```

### Data model

No database. Listing pages scan `output/runs/` and `output/eval/`; detail
pages read the run dir's files. The live registry
(`dict[run_id, RunWorker]`) holds only in-flight runs; it is **not** the
source of truth, the filesystem is. On startup the registry scans
`output/runs/*` and marks any dir lacking `report.html` (and not live) as
`interrupted` so a server restart never hides a half-finished run.

### CLI refactor (minimal, additive)

Extract `cli.main`'s steps 2–9 (after arg parsing and input acquisition) into
`pipeline.run_pipeline(...)`. The CLI becomes: parse args → acquire inputs →
build client → call `run_pipeline`. Tests for `cli.main` stay green because
behaviour is identical; the new `test_pipeline.py` covers `run_pipeline`
directly.

## Visual & UX design — "Case File"

The webapp presents each triage run as a **physical case file in an analyst's
archive**. Every screen adopts a printed-form / manila-folder aesthetic so the
page reads as paper, not as a SaaS dashboard. The signature element is a
**rubber-stamp status mark** applied to each run (REVIEWED / RUNNING /
FAILED / INTERRUPTED): rotated ~−6°, oxblood, slightly distressed, placed
over the manifest header.

### Token system

Color (6 named):
- `paper`  `#EFEADF` — manila-folder buff (material-of-the-artifact, deliberately
  warmer/dustier than the cream default; this is the file folder the report
  would actually live in)
- `ink`    `#1F1E1B` — near-black, slightly warm
- `oxblood` `#7A2F26` — signature accent + High severity (rubber stamp)
- `ochre`  `#9A6B1A` — Medium severity
- `sage`   `#5C6E4B` — Low severity (muted, not bright green)
- `hairline` `#C5BEAD` — column rules and box borders

Type (3 roles, 3 families — deliberate pairing, not one superfamily):
- **Display:** *Spectral* (a serif with optical sizing and a quietly literary
  tone — gives the "report" its authority; uncommon enough not to read as
  default)
- **Body:** *IBM Plex Sans* (engineered, neutral — explicitly not Inter)
- **Data:** *JetBrains Mono* (RUN IDs, host:port, CVSS, labels, the marginal
  rank numbers — the vernacular of scanner output and the form itself)

Layout:
- Top: a folder-tab strip (Runs · New run · Eval) — tabs, not nav links,
  because the metaphor is a folder.
- Run detail = a **manifest header** (pre-printed form fields: RUN ID /
  STARTED / PROVIDER / MODEL / INPUTS / FINDINGS), a stamped status mark in
  the top-right corner of the manifest, the live progress log below it in a
  rules-bordered "log slip" box (monospace, last line at bottom), and when
  done, the embedded report in an `<iframe src="/runs/<id>/report.html">`.
- Findings are rendered by the existing report template (which already has
  the severity badges/bars) — the webapp does not restyle them, so the
  standalone artifact and the in-app artifact are identical.
- Marginal rank numbers sit in the left gutter of the findings table, like
  line numbers in a printed log.

Signature (the one memorable thing):
- The rubber-stamp status mark. Everything else is quiet: hairline rules,
  pre-printed form boxes, no shadows, no gradients, no rounded corners
  beyond a 2px form-field chamfer. Boldness is spent here, not spread around.

Restraint: responsive down to mobile (folder tabs collapse to a select), visible
keyboard focus (oxblood focus ring on form fields), `prefers-reduced-motion`
disables the only animation (the stamp "lands" with a 200ms scale-in on done).

## Step-by-step plan

1. **Refactor**: extract `run_pipeline(...)` into `src/vulntriage/pipeline.py`;
   `cli.main` calls it. Add `test_pipeline.py` (mock client). Verify `pytest` green.
2. **Deps**: add `fastapi`, `uvicorn`, `python-multipart` to `pyproject.toml`;
   `uv sync`. Add `[project.scripts] vulntriage-web = "vulntriage.webapp.app:run"`.
3. **Run registry**: `src/webapp/runs.py` — `RunRegistry` (in-memory),
   `RunWorker` thread with per-worker stdout capture, state machine, recovery
   scan of `output/runs/` on startup.
4. **FastAPI app**: `src/webapp/app.py` — routes above; static + Jinja2
   env pointed at `src/webapp/templates`.
5. **Templates**: the 8 page templates + 3 partials implementing the Case
   File design system; `static/style.css` + `static/app.js` (polling only).
6. **Eval wiring**: `POST /eval/new` calls `run_experiment` in a thread;
   `/eval/<id>` renders `metrics.json` as a table (per-cell mean ± std) and
   links to the raw file. Reuses the existing `output/eval/<ts>/` layout.
7. **Nuclei-from-web**: the "New run" intake form has a "Scan target" mode
   that runs `run_nuclei` then continues into triage in the same worker.
8. **Tests**: `test_webapp.py` with FastAPI `TestClient` — dashboard
   renders, `POST /runs/new` with the sample dataset + a mock client
   injected reaches `done` and serves `report.html`; eval list renders.
9. **Lint/format**: `ruff check --fix`, `ruff format`.
10. **Docs**: README "Web interface" section (`uv run uvicorn vulntriage.webapp.app:app --reload`),
    THESIS_WRITEUP new §17 "Web Interface" describing routes, run model,
    and the Case File design.
11. **Run it**: a manual smoke `uv run uvicorn vulntriage.webapp.app:app`
    against the sample dataset with a mock client (or a local model) to
    eyeball the dossier + stamp + iframe report.

## Files / Areas Likely Affected

```
pyproject.toml                        # +fastapi, +uvicorn, +python-multipart, +script
src/vulntriage/cli.py                 # calls run_pipeline (slimmed)
src/vulntriage/pipeline.py            # NEW: shared run logic
src/webapp/                           # NEW: app, runs, templates, static
tests/test_pipeline.py                # NEW
tests/test_webapp.py                  # NEW
README.md                             # + Web interface section
docs/specs/webapp-design.md           # THIS
docs/THESIS_WRITEUP.md                # + §17 Web Interface
```

## Validation

- `uv run pytest` green, `ruff check`/`format` clean.
- `uv run uvicorn vulntriage.webapp.app:app --reload` serves `/`; the
  dashboard lists any existing `output/runs/*` and `output/eval/*`.
- Submitting the "New run" form (sample dataset, mock client) drives a run to
  `done`; `/runs/<id>` shows the stamped manifest, the live log while
  running, and the embedded report once complete.
- `/runs/<id>/report.html` is byte-identical to the file the CLI would write
  to the same dir.
- Past CLI runs (created before/without the server) appear in `/runs` with
  status recovered from disk.
- `/eval/new` with the example config reaches `done` and `/eval/<id>`
  renders a per-cell metrics table.