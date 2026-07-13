# Implementation Plan: Triage Pipeline v2

Source spec: `docs/specs/triage-pipeline-v2-design.md`

Conventions:
- Each task ends with a green check (`Definition of Done`) — don't move on until it passes.
- Tasks within a phase are ordered by dependency; phases are sequential.
- Run `uv run ruff check --fix` and `uv run ruff format` after every file change.
- Tests live under `tests/` and run with `uv run pytest`.
- Follow the v1 patterns: Pydantic models, `LLMClient` injection, structured-JSON LLM output with best-effort parsing.

---

## Phase 0 — Foundation

### Task 0.1 — Add v2 dependencies
- Add to `pyproject.toml`: `jinja2>=3.1`, `weasyprint>=60`, `scipy>=1.13`.
- Add `pytest>=8` and `pytest-mock>=3` to a `[dependency-groups] dev` section.
- Run `uv sync`.
- **DoD:** `uv sync` succeeds; `uv run python -c "import jinja2, weasyprint, scipy, pytest"` exits 0.

### Task 0.2 — Create output directories & gitignore entries
- Create `output/eval/`, `output/reports/`, `data/templates/`, `tests/`.
- Ensure `.gitignore` covers `output/eval/*`, `output/reports/*` (keep the dirs via `.gitkeep`).
- **DoD:** directories exist; `git status` shows the dirs tracked but contents ignored.

---

## Phase 1 — Data Layer

### Task 1.1 — Expand the synthetic dataset with ground truth
- Rewrite `data/synthetic_findings.json` to ~20 findings across services: Redis, SSH, Tomcat, MySQL, nginx, Jenkins, Elasticsearch, MongoDB, Grafana, Postgres, plus 2-3 no-CVE misconfigurations.
- Each finding gains a `ground_truth` object: `{ "exploit_maturity": "H|F|P|U|X", "label": "High|Medium|Low" }` following the spec's mapping table. No-CVE findings use `"exploit_maturity": "X"`.
- Mix exposure (internet-facing vs internal) and CVSS (critical/high/medium/low/none).
- **DoD:** `uv run python -c "import json; d=json.load(open('data/synthetic_findings.json')); assert len(d)>=15; assert all('ground_truth' in f for f in d)"` passes; label distribution has at least 2 each of High/Medium/Low.

### Task 1.2 — Build the RAG knowledge base
- Create `data/cve_kb.json`: a list of entries `{cve, service, summary, remediation_steps[]}`.
- Cover every CVE referenced in the expanded synthetic dataset (Task 1.1). Add 2-3 service-class entries (keyed by service, no CVE) for no-CVE findings.
- **DoD:** JSON validates; every CVE in `synthetic_findings.json` has a matching entry in `cve_kb.json` (assert via a small script).

---

## Phase 2 — Models & Scorer Change

### Task 2.1 — Add `RemediatedFinding` model
- In `models.py`, add `RemediatedFinding(PrioritizedFinding)` with fields: `remediation_steps: list[str]`, `remediation_rationale: str = ""`, `rag_hits: list[str] = Field(default_factory=list)`, `remediation_model: str | None = None`.
- **DoD:** `uv run python -c "from vulntriage.models import RemediatedFinding; print(RemediatedFinding.model_fields.keys())"` shows the new fields.

### Task 2.2 — Add `few_shot` parameter to the scorer
- In `scorer.py`, refactor the few-shot examples block into a constant `FEW_SHOT_BLOCK`.
- Add `few_shot: bool = True` to `score()` and `score_all()`. When `False`, omit `FEW_SHOT_BLOCK` from `USER_TEMPLATE`.
- Default `True` preserves v1 behavior.
- **DoD:** `score_all(enriched, client, few_shot=False)` runs without the examples block; `score_all(..., few_shot=True)` matches v1 output shape. Add a unit test asserting the zero-shot prompt string does not contain "Example 1".

---

## Phase 3 — Remediator Module

### Task 3.1 — KB loader
- In `remediator.py`, add `load_kb(path) -> list[dict]` and `lookup(kb, cve=None, service=None) -> list[dict]` returning matches (CVE match first, then service-class fallback).
- **DoD:** unit test: given the real `cve_kb.json`, `lookup` returns the right entry for a known CVE and an empty list for an unknown one.

### Task 3.2 — Remediation LLM call
- Add `remediate(finding: PrioritizedFinding, client: LLMClient, kb: list[dict] | None, use_rag: bool = True) -> RemediatedFinding`.
- If `use_rag` and KB hits exist, inject `summary` + `remediation_steps` into the prompt as grounding context; set `rag_hits` to the matched CVEs/services.
- Prompt returns structured JSON `{steps: [...], rationale: "..."}`; reuse the `_extract_json_field`-style parsing pattern from `enricher.py` (factor a shared helper if it reduces duplication, but keep it minimal).
- **DoD:** with a mock `LLMClient` returning canned JSON, `remediate` produces a `RemediatedFinding` with parsed steps; `rag_hits` populated when KB has a match, empty when `use_rag=False`.

### Task 3.3 — `remediate_all`
- Add `remediate_all(findings, client, kb_path=None, use_rag=True) -> list[RemediatedFinding]` with progress logging matching v1 style.
- **DoD:** unit test with mock client over 3 findings returns 3 `RemediatedFinding` objects.

---

## Phase 4 — Report Composer

### Task 4.1 — Jinja2 HTML template
- Create `data/templates/report.html`: executive summary (total findings, severity counts), risk breakdown (CSS bar widths per finding), per-finding detail (rank, label, host/port, CVE, CVSS, risk score, context, exploitability rationale, remediation steps), ranked summary table.
- Use a `{{ findings }}` list of dicts and a `{{ summary }}` dict context.
- **DoD:** template renders with a sample context dict (Jinja2 `Environment` + `get_template`); no undefined errors.

### Task 4.2 — Composer functions
- In `report_composer.py`, add:
  - `_build_context(findings: list[RemediatedFinding]) -> dict`
  - `render_html(findings) -> str`
  - `write_html(findings, path) -> Path`
  - `write_pdf(findings, path) -> Path` (WeasyPrint `HTML(string=...).write_pdf`)
  - `compose(findings, html_path=None, pdf_path=None) -> dict` returning paths written.
- **DoD:** unit test renders HTML for 2 sample findings and writes a 1-page PDF to a temp path; PDF file is non-empty.

---

## Phase 5 — Evaluation Harness

### Task 5.1 — Ground-truth loader & label mapping
- In `evaluation.py`, add `load_ground_truth(path) -> dict[str, dict]` keyed by finding `id`, and `maturity_to_label(m: str) -> str | None` implementing the spec's mapping table (H/F→High, P→Medium, U→Low, X/None→None).
- **DoD:** unit test: the mapping returns `None` for `"X"`, `"High"` for `"H"` and `"F"`, `"Medium"` for `"P"`, `"Low"` for `"U"`.

### Task 5.2 — Metric functions
- Add pure functions operating on lists, no LLM:
  - `precision_recall_f1(predicted, actual) -> dict` (macro over High/Medium/Low; skip `None` actuals).
  - `spearman_rank(predicted_order, actual_order) -> float` via `scipy.stats.spearmanr`.
  - `cvss_only_rank(findings) -> list[str]` (rank by CVSS desc; no-CVE/None CVSS sorted last).
- **DoD:** unit test on a 3-finding known dataset with hand-computed expected F1 and rank correlation.

### Task 5.3 — Manual-triage throughput model
- Add `estimate_manual_seconds(findings, seconds_per_finding=300) -> float` (configurable; default 5 min/finding per literature default — value documented, easily changed).
- **DoD:** unit test: 4 findings → 1200s.

### Task 5.4 — Single-run capture
- Add `run_once(input_path, provider, model, few_shot, use_rag, asset_registry) -> RunResult` where `RunResult` holds scored/prioritized/remediated lists, per-module latencies, total tokens, wall-clock.
- Reuse existing `enrich_all`, `score_all`, `prioritize`, `remediate_all`. Wrap timing around each module.
- Capture token usage by extending `LLMClient.complete` to expose last usage, or by summing printed token logs — prefer returning usage from `complete` (additive change to the protocol; keep backward compatible).
- **DoD:** with a mock client, `run_once` returns a `RunResult` with populated latency dict and non-zero token count.

### Task 5.5 — Experiment runner
- Add `run_experiment(config) -> ExperimentResult` that iterates the 12 cells (3 models × 2 prompt strategies × 2 RAG) × 3 runs, calling `run_once` and aggregating metrics (mean + std per cell).
- Config is a dataclass/YAML defining the 3 model specs (`provider`, `model`) and dataset path.
- Writes `output/eval/metrics.json` (per-cell aggregates) and `output/eval/results.csv` (one row per cell-run with raw metrics). Includes baseline rows: CVSS-only ranking Spearman, manual-triage seconds.
- **DoD:** with mock clients, a 2-model × 1-strategy × 1-RAG mini-config produces a `results.csv` with the expected number of rows and a `metrics.json` with mean/std; CVSS-only and manual baselines present.

---

## Phase 6 — CLI Integration

### Task 6.1 — New CLI flags
- In `cli.py`, add: `--remediate` (flag), `--output-format {text,html,pdf,both}` (default text), `--rag/--no-rag` (default rag), `--prompt-strategy {few-shot,zero-shot}` (default few-shot), `--evaluate` (flag), `--eval-config` (path).
- When `--evaluate` is set, delegate to `evaluation.run_experiment` and exit (ignore normal pipeline flow).
- **DoD:** `uv run python main.py --help` lists all new flags; invalid combos print a clear error.

### Task 6.2 — Wire remediator + composer into the pipeline
- After prioritize, if `--remediate`, run `remediate_all` with `use_rag` from flags.
- If `--output-format` is text, keep v1 `reporter.render`. For html/pdf/both, call `report_composer.compose` writing under `output/reports/` (or `--output` path).
- `--save-intermediates` now also dumps `remediated.json`.
- Pass `few_shot` from `--prompt-strategy` into `score_all`.
- **DoD:** smoke command from spec Validation section runs end-to-end and writes both `report.html` and `report.pdf`.

---

## Phase 7 — Tests & Lint

### Task 7.1 — Test suite
- `tests/test_remediator.py`: KB lookup (hit/miss), `remediate` with mock client (RAG on/off), `remediate_all`.
- `tests/test_report_composer.py`: `_build_context`, `render_html`, `write_pdf` (non-empty file).
- `tests/test_evaluation.py`: maturity mapping, precision/recall/F1, Spearman, CVSS-only rank, manual estimate, `run_once` with mock client, mini `run_experiment`.
- `tests/test_scorer_fewshot.py`: zero-shot vs few-shot prompt strings.
- Use `pytest` fixtures; mock `LLMClient` via a tiny stub class returning canned JSON.
- **DoD:** `uv run pytest` green; `uv run pytest --cov=vulntriage` reports reasonable coverage on new modules.

### Task 7.2 — Lint & format
- `uv run ruff check --fix` and `uv run ruff format` across `src/` and `tests/`.
- **DoD:** ruff clean.

---

## Phase 8 — Experiment Execution & Docs

### Task 8.1 — Run the full experiment
- Run all 12 cells × 3 runs on the expanded dataset (start with free/local models; paid cloud last).
- Verify `metrics.json` and `results.csv` populate; spot-check a few cells' accuracy numbers.
- **DoD:** `results.csv` has 36 condition-run rows + baseline rows; metrics look sane (no NaNs, F1 in [0,1]).

### Task 8.2 — Update README
- Document v2 modules table, new CLI flags, eval workflow (`--evaluate --eval-config`), how to reproduce experiments, and the CVSS-E ground-truth mapping.
- **DoD:** README's Quick start includes a v2 remediate+report example and an eval example; pipeline diagram updated to include remediator + report composer.

---

## Dependency Summary

```
0.1, 0.2 (no deps)
1.1 -> 1.2
2.1 -> 3.2, 4.2
2.2 -> 6.1
1.2 -> 3.1
3.1 -> 3.2 -> 3.3 -> 6.2
4.1 -> 4.2 -> 6.2
5.1 -> 5.2 -> 5.5
5.3 (no dep)
5.4 -> 5.5 -> 6.1
6.1 -> 6.2 -> 7.1 -> 7.2 -> 8.1 -> 8.2
```

## Suggested execution order
0.1 → 0.2 → 1.1 → 1.2 → 2.1 → 2.2 → 3.1 → 3.2 → 3.3 → 4.1 → 4.2 → 5.1 → 5.2 → 5.3 → 5.4 → 5.5 → 6.1 → 6.2 → 7.1 → 7.2 → 8.1 → 8.2
