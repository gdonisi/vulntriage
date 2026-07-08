# System Description for Thesis — LLM-Enabled Vulnerability Triage Pipeline

This document describes everything built (v1 + v2) in a structured way you can
adapt into your thesis chapters (Methodology, Implementation, Evaluation). Each
section corresponds to a logical unit of the system.

---

## 1. System Overview

The system is a modular, extensible pipeline that ingests network scanner
results, enriches them with LLM-generated threat context, scores exploitability
(High/Medium/Low), prioritizes findings by composite risk, generates
remediation recommendations (optionally grounded in a curated knowledge base),
and produces final reports in plain-text, HTML, and PDF formats.

An evaluation harness runs the full pipeline under controlled conditions
(3 models × 2 prompt strategies × 2 RAG settings × 3 repeats = 36 runs) and
computes metrics that directly answer the thesis question.

**Architecture**: Every module has exactly one job, receives a typed Pydantic
model, returns a typed Pydantic model. The LLM is injected as a client, not
imported globally — making every module independently testable and
provider-swappable.

**Data flow (v2 full pipeline)**:

```
Scanner output (Nmap XML / Nuclei JSONL / OpenVAS CSV / synthetic JSON)
  → Parser            → List[RawFinding]
  → Context Enricher  (LLM) → List[EnrichedFinding]
  → Exploitability Scorer (LLM) → List[ScoredFinding]
  → Prioritizer       (formula) → List[PrioritizedFinding]
  → Remediator        (LLM + RAG) → List[RemediatedFinding]
  → Report Composer   (Jinja2 / WeasyPrint) → HTML + PDF
```

---

## 2. Data Models (`models.py`)

Six Pydantic models form a strict inheritance chain, each adding fields:

| Model | Extends | Key added fields | Source |
|---|---|---|---|
| `RawFinding` | — | `id`, `source`, `host`, `port`, `service`, `description`, `cvss`, `cve` | Parser output |
| `EnrichedFinding` | `RawFinding` | `context` (threat analysis), `enrichment_model` | Enricher output |
| `ScoredFinding` | `EnrichedFinding` | `exploitability` (High/Medium/Low enum), `exploitability_rationale`, `scoring_model`; plus three optional ensemble fields — `exploitability_votes` (dict[str,str]), `ensemble_quorum` (int\|None), `ensemble_unresolved` (bool) — empty/None/False for single-model runs | Scorer output |
| `PrioritizedFinding` | `ScoredFinding` | `asset_criticality` (float), `risk_score`, `rank` | Prioritizer output |
| `RemediatedFinding` | `PrioritizedFinding` | `remediation_steps` (list[str]), `remediation_rationale`, `rag_hits`, `remediation_model` | Remediator output |

`Exploitability` is a `StrEnum` with values `HIGH`, `MEDIUM`, `LOW` and a
`.numeric()` method returning 1.0, 0.5, 0.1 respectively — used by the
prioritizer formula. Note that `Unresolved` is **not** an `Exploitability` enum
member: in ensemble mode an unresolved finding keeps a High/Medium/Low
`exploitability` (the highest tally label, so the deterministic prioritizer
still ranks it) and is flagged via the separate `ensemble_unresolved` boolean;
this leaves `Exploitability.numeric()` and the CVSS-E accuracy metric (scoped
to High/Medium/Low) untouched.

---

## 3. LLM Client (`llm.py`)

**`LLMClient`** is a Protocol (structural interface) requiring:
- `model: str`
- `total_tokens: int` (best-effort accumulator)
- `complete(system: str, user: str) -> str`

**`OpenAICompatibleClient`** is the real implementation. It wraps the OpenAI
SDK and supports nine built-in providers plus a `custom` provider via
`make_client()` factory:
- `lmstudio` — local, base URL `http://localhost:1234/v1`
- `ollama` — local, `http://localhost:11434/v1`
- `llamacpp` / `vllm` — local alternatives
- `openai` — cloud, requires `OPENAI_API_KEY`
- `openrouter` — cloud, requires `OPENROUTER_API_KEY`
- `anthropic` / `google` / `deepseek` — cloud alternatives, API key required
- `custom` — arbitrary OpenAI-compatible endpoint; `--base-url` is required,
  `--api-key` is optional, `--local` marks it as self-hosted for
  `--local-only` gating. The webapp shows inline fields (base URL, API key,
  local checkbox) when `custom` is selected, and the model picker fetches
  from the custom endpoint's own `/models` route.

Each provider can be configured with `--reasoning-effort low|medium|high` for
models that support chain-of-thought reasoning; provider support varies and
the flag is omitted entirely for standard (non-reasoning) models. Temperature is fixed at 0.2
for reproducibility. Token usage is captured from API response metadata when
available. Each client is tagged with a `local` flag (`True` for self-hosted
providers, `False` for cloud). It is not part of the request path; the CLI
`--local-only` flag uses the same `LOCAL_PROVIDERS` set
(`lmstudio`/`ollama`/`llamacpp`/`vllm`) to refuse cloud providers before any
network call is made.

**Provider configuration** is centralized in `_provider_config(provider, *, base_url, api_key, local)`
returning `(base_url, api_key, local)`; both `make_client` (chat completions)
and `list_models` (model enumeration) route through it so they never disagree
about the base URL or auth. For `custom` providers the three keyword arguments come
directly from the CLI flags (`--base-url`, `--api-key`, `--local`); for built-in
providers they are ignored and the hardcoded defaults are used.

**Model enumeration** (`list_models(provider) -> list[str]`) queries each
provider's OpenAI-compatible `GET /models` endpoint
(`client.models.list()`), parsing `data[].id` defensively (with `body.model`
/ `model` fallbacks). It is strictly best-effort: on any error (endpoint
missing, auth, transport) it returns `[]` so callers — the webapp model
picker — can fall back to free-text input. The webapp exposes it at
`GET /models?provider=...` returning `{"models": [...], "error": null|str}`;
a cloud key is never exposed to the browser, the call is server-side.

---

## 4. Parser (`parser.py`)

Auto-detects format from file extension:

| Extension | Format | Parser | Key implementation |
|---|---|---|---|
| `.xml` | Nmap XML | `xml.etree.ElementTree` | Iterates `<port>` elements with state="open", extracts service + product + version |
| `.jsonl` | Nuclei JSONL | Line-by-line `json.loads` | Extracts template-id, name, severity, CVSS score, CVE-ID from the classification block |
| `.json` | Synthetic | `json.loads` | Reads array of items with our schema (used for test data) |
| `.csv` | OpenVAS CSV | `csv.DictReader` | Reads GSA CSV export; extracts IP, port, NVT name, summary, CVSS, CVEs, affected software |

All parsers normalize to `list[RawFinding]`. Findings get unique IDs prefixed
by source (`nmap-…`, `nuclei-…`, `openvas-…`, `synthetic-…`).

---

## 5. Context Enricher (`enricher.py`)

For each `RawFinding`, sends a templated prompt to the LLM asking for:

> *"3-4 sentences covering: what is vulnerable, real-world attack scenarios,
> and business impact"*

Returns structured JSON with a single `"context"` field. Falls back to regex
extraction if the LLM response isn't valid JSON. Creates an `EnrichedFinding`
with the context text and the model name.

---

## 6. Exploitability Scorer (`scorer.py`)

For each `EnrichedFinding`, asks the LLM to rate exploitability:

- **Few-shot** (default, equivalent to v1): includes two worked examples in
  the prompt — a Redis instance rated High, an internal SSH service rated Low.
- **Zero-shot**: omits the examples, just gives the instruction.

Returns JSON with `"exploitability"` (High/Medium/Low) and `"rationale"`. A
`_coerce_label()` function handles fuzzy LLM output (e.g. "high" → `HIGH`).
Fallback for unparseable responses: if CVSS >= 7.0, default to Medium; else
Low.

### 6.1 Multi-LLM ensemble (scoring only)

`score_all` accepts two optional parameters — `clients: list[LLMClient] |
None` and `quorum: int | None` — that fan out only the exploitability scorer
across N models. Enrichment, prioritization, remediation, and report
composition still run once on the primary client; the primary
(`--provider`/`--model`) is the **first** ensemble member and is used for
enrichment + remediation. The single-model path (`clients is None`) is
byte-identical to v1 and (with `clients set`) the merge runs:

1. Each finding is scored once per client, collecting `{client.model: label}`
   into `exploitability_votes`.
2. A strict-majority quorum is applied: if `quorum is None` it defaults to
   `⌊N/2⌋ + 1` (a genuine majority — for even N this requires unanimity, for
   odd N a bare majority).
3. If any label's tally ≥ quorum, that label is the final `exploitability` and
   `ensemble_unresolved = False`.
4. Else `ensemble_unresolved = True`; `exploitability` is set to the highest
   tally label (so the deterministic prioritizer still ranks it somewhere
   sane) while the report renders it as **Unresolved**.
5. `exploitability_rationale` is a fully transparent tally+quorum summary,
   e.g. `"2/3 models: High=2, Medium=1 (quorum 2 -> High)"` (or
   `"0/3 models: High=1, Medium=1, Low=1 (quorum 2 -> unresolved -> fallback High)`
   when no label reaches quorum).

**Why scoring-only, and why strict-majority** are recorded in
`docs/specs/ensemble-and-model-picker-design.md`. In short: the exploitability
label is the one categorical triage decision where false positives concretely
bite, so merging is a clean auditable vote; and strict majority (not
plain-majority-with-tiebreak) guarantees that a lone High from one model
**never** silently becomes a final High — disagreements are surfaced as
`Unresolved` to the human instead of being handed a confident guess.
Unresolved findings are excluded from the High/Medium/Low accuracy metric
(no ground-truth match) but retained for ranking and latency.

---

## 7. Prioritizer (`prioritizer.py`)

Pure logic — no LLM calls. Computes composite risk score:

```
Risk = (CVSS/10 × 0.5) + (Exploitability_numeric × 0.3) + (Asset_criticality × 0.2)
```

- CVSS normalized to 0–1 (divide by 10; missing CVSS defaults to 5.0)
- Exploitability: High=1.0, Medium=0.5, Low=0.1
- Asset criticality: loaded from YAML registry (host → float)

Loads asset criticality from a YAML file (host → criticality pairs). Sorts
descending by risk score and assigns ranks 1..N.

---

## 8. Remediator (`remediator.py`) [v2, new]

Generates remediation steps for each `PrioritizedFinding` using the LLM.

**Light RAG**: Before calling the LLM, looks up the finding's CVE (then
service-class as fallback) in a curated JSON knowledge base
(`data/cve_kb.json`). If hits exist, their summary and known remediation steps
are injected into the prompt as grounding context. RAG hits are recorded in
`rag_hits` for traceability.

**Toggle**: `use_rag=True` (default) enables the lookup; `use_rag=False` skips
it entirely — the LLM generates remediation from its own knowledge.

**Knowledge base schema** (`cve_kb.json`):
```json
[
  {
    "cve": "CVE-2022-0543",
    "service": "Redis",
    "summary": "...",
    "remediation_steps": ["Step 1", "Step 2"]
  },
  {
    "cve": null,
    "service": "Redis",
    "summary": "Generic Redis hardening",
    "remediation_steps": ["Use protected-mode", "Require AUTH"]
  }
]
```

Entries with `cve: null` serve as service-class fallbacks when no CVE-specific
entry exists. The KB covers 11 CVE-specific entries and 7 service-class
entries across Redis, SSH, Tomcat, MySQL, nginx, Jenkins, Elasticsearch,
MongoDB, Grafana, and Postgres.

---

## 9. Report Composer (`report_composer.py`) [v2, new]

Renders findings into reports using a single Jinja2 HTML template
(`data/templates/report.html`). Sections:

1. **Executive Summary** — total findings, High/Medium/Low counts, top
   priority finding description
2. **Risk Breakdown** — horizontal bar chart per finding: each bar fill's
   width is proportional to the finding's risk score (`width = risk_score ×
   100%`), coloured by exploitability tier (red/orange/green). The `.bar-fill`
   element is `display: block` so the percentage width applies (inline spans
   ignore `width`).
3. **Technical Findings** — per-finding card with host, port, CVE, CVSS, risk
   score, context, exploitability rationale, remediation steps with rationale,
   RAG references
4. **Ranked Summary Table** — all findings in a table (Rank, Score,
   Exploitability, Finding, Host)

WeasyPrint converts the HTML to PDF. Both formats share the same template;
output is controlled by `--output-format` (text|html|pdf|both). The composer
accepts `RemediatedFinding` (full report with `--remediate`) **or** plain
`PrioritizedFinding` (HTML/PDF rendered without `--remediate`); in the latter
case remediation fields are read via `getattr` defaults and the remediation
sections render empty, so `--output-format html/pdf/both` works on its own.

**Ensemble rendering** (v3): when a finding carries `exploitability_votes`,
the card renders a vote-breakdown box and, if `ensemble_unresolved`, an
`Unresolved` badge (distinct grey, separate from the High/Med/Low colours).
The High/Medium/Low counts in the summary exclude unresolved findings, which
instead get their own `Unresolved` tile; the executive summary appends a
sentence naming the ensemble size, quorum, and Unresolved count. The plain-text
reporter (`reporter.py`) prints `[UNRESOLVED]` for unresolved rows in the rank
table and a per-model `Votes:` line per finding when votes exist.

---

## 10. Evaluation Harness (`evaluation.py`) [v2, new]

The core of the thesis experiment. Runs the pipeline under a controlled grid
of conditions and computes metrics.

### 10.1 Ground Truth

The 20 synthetic findings each carry a `ground_truth` field:
```json
{
  "id": "synthetic-0",
  "ground_truth": {
    "exploit_maturity": "H",
    "label": "High"
  }
}
```

**CVSS-E → label mapping**:

| CVSS-E | Meaning | Label |
|---|---|---|
| H / F | functional exploit available | High |
| P | proof-of-concept available | Medium |
| U | unproven / no exploit | Low |
| X / None | no temporal data | **Excluded from accuracy** |

### 10.2 Metrics

For each pipeline run, computed against ground truth:

| Metric | Implementation | What it measures |
|---|---|---|
| **Precision** | Macro-averaged per-class | Of findings predicted High/Medium/Low, how many were actually that class |
| **Recall** | Macro-averaged per-class | Of actually-High/Medium/Low findings, how many were correctly predicted |
| **F1** | Macro-averaged per-class | Harmonic mean of precision and recall |
| **Pipeline Spearman ρ** | `scipy.stats.spearmanr(pipeline_risk_scores, gt_priority_values)` | How well the pipeline's risk score ordering matches the ground-truth ordering |
| **CVSS-baseline Spearman ρ** | `spearmanr(cvss_only_values, gt_priority_values)` | Same correlation, but using only CVSS base scores |
| **Pipeline wall-clock** | `time.perf_counter()` across `run_once()` | End-to-end latency |
| **Manual triage estimate** | `n_findings × 300 seconds` | Modelled analyst effort (5 minutes per finding) |
| **Throughput ratio** | `manual_seconds / pipeline_seconds` | How much faster/slower than manual review |
| **Token usage** | `client.total_tokens` | Proxy for LLM cost |

### 10.3 Baseline Comparisons

Two baselines are computed alongside every experiment run:

1. **CVSS-only ranking** — Spearman ρ of raw CVSS base scores vs ground-truth
   priority, showing what you get without LLM enrichment.
2. **Manual triage time** — 5 minutes per finding (300 s), a commonly cited
   order-of-magnitude estimate from security triage literature.

### 10.4 Experiment Design

**12 conditions × 3 repeats = 36 runs per experiment**:

| Dimension | Values | Rationale |
|---|---|---|
| Model | 3 (one local small, one local medium, one cloud) | Compare cost-accuracy tradeoffs |
| Prompt strategy | `few-shot` / `zero-shot` | Measure the value of examples |
| RAG | `on` / `off` | Measure the value of grounded knowledge |
| Repeats | 3 per condition | Capture variance from LLM non-determinism |

Outputs: `output/eval/<ts>/metrics.json` (per-cell mean + std for each metric)
and `output/eval/<ts>/results.csv` (one row per run, 36 + 2 baseline rows) —
timestamped so previous eval runs are never overwritten.

### 10.5 `gt_value` — Ground Truth Priority Value

For ranking comparisons, we compute a numeric priority: `label_numeric × 100 + CVSS`.
The class (High=1.0, Medium=0.5, Low=0.1) dominates via the ×100 multiplier,
so a Medium with high CVSS never outranks a Low. CVSS only breaks ties within
a class.

---

## 11. CLI (`cli.py`)

Single entry point via `main.py`. Command-line flags:

| Flag | v1/v2 | Description |
|---|---|---|
| `--input` | v1 | One or more scanner output files (XML/JSONL/JSON/CSV); findings are merged |
| `--scan` | v1 | Run dockerized scanner (nuclei or nmap), then continue to triage (unless `--scan-only`) |
| `--target` | v1 | Target for `--scan` |
| `--provider` | v1 | LLM provider (lmstudio/ollama/openai/openrouter/…/custom) |
| `--base-url` | v3 | Required when `--provider custom`: the OpenAI-compatible endpoint URL |
| `--api-key` | v3 | Optional API key for custom providers |
| `--local` | v3 | Marks a custom provider as self-hosted (for `--local-only` gating) |
| `--model` | v1 | Model name |
| `--reasoning-effort` | v1 | Thinking/reasoning effort for models that support it (provider support varies) |
| `--local-only` | v2 | Block cloud providers; only local backends allowed (lmstudio/ollama/llamacpp/vllm) |
| `--asset-registry` | v1 | YAML file with host→criticality |
| `--output` | v1/v2 | Dir for HTML/PDF/eval (default: timestamped under `output/runs` or `output/eval`); file path for text (default: stdout) |
| `--output-format` | v2 | text/html/pdf/both |
| `--remediate` | v2 | Run remediation generator |
| `--rag` / `--no-rag` | v2 | Toggle RAG grounding |
| `--kb` | v2 | Path to RAG knowledge base |
| `--prompt-strategy` | v2 | few-shot (default) / zero-shot |
| `--ensemble` | v3 | Comma-separated extra scoring models (`provider:model`, split on first colon); scorer fans out across them, `--provider`/`--model` is the primary and first member |
| `--quorum` | v3 | Strict-majority quorum for `--ensemble` (default `floor(N/2)+1`); below quorum → finding flagged Unresolved |
| `--web` | v3 | Start the local web interface (alias for `uvicorn vulntriage.webapp.app:app`) |
| `--evaluate` | v2 | Run the evaluation experiment grid |
| `--eval-config` | v2 | JSON config file for multi-model grid |
| `--repeats` | v2 | Repeats per condition in eval mode |
| `--save-intermediates` | v2 | Dump intermediate pipeline outputs (optional dir; default `<run_dir>/intermediates/`) |
| `--scan-only` | v1 | Just scan, skip triage |
| `--help` | v1/v2 | Show all flags |

---

## 12. Data Layer

### 12.1 Synthetic Dataset (`data/synthetic_findings.json`)

20 findings covering 10 services (Redis, SSH, Tomcat, MySQL, nginx, Jenkins,
Elasticsearch, MongoDB, Grafana, Postgres) with varied CVE/no-CVE, CVSS
0.0–9.8, internet-facing vs internal exposure. Ground truth distribution:
9 High, 6 Medium, 5 Low.

### 12.2 Asset Registry (`data/assets.yaml`)

5 hosts (192.168.1.10–.50) with criticalities 1.0, 0.5, 0.8, 0.3, 1.0.

### 12.3 RAG Knowledge Base (`data/cve_kb.json`)

18 entries: 11 CVE-specific (e.g. CVE-2022-0543 Redis, CVE-2021-44228 Log4j,
CVE-2024-23897 Jenkins) + 7 service-class fallbacks. Each entry has
`{cve, service, summary, remediation_steps[]}`.

### 12.4 HTML Template (`data/templates/report.html`)

Jinja2 template with inline CSS. Sections: header, executive summary, risk
breakdown bars (fill width = risk score × 100%, colour by exploitability),
per-finding cards with remediation, ranked table. In ensemble mode each
finding card also renders an `Unresolved` badge (distinct grey, separate from
the High/Med/Low colours) and a vote-breakdown box (`model=label, ...`); the
executive summary gains a sentence naming the model count, quorum, and
Unresolved count, and the summary grid adds an `Unresolved` stat tile.

### 12.5 Output Layout

Each triage run writes to its own timestamped directory so previous results
are never overwritten:

- **`output/runs/<YYYYMMDD-HHMMSS>/`** — `report.html`, `report.pdf` for
  `--output-format html|pdf|both` (text still goes to stdout unless `--output`
  is a file). `--output <dir>` overrides the directory.
- **`output/eval/<YYYYMMDD-HHMMSS>/`** — `metrics.json`, `results.csv` for
  `--evaluate` (`--output` or the eval config's `output_dir` override).
- **`<run_dir>/intermediates/`** — enriched/scored/prioritized/remediated JSON
  when `--save-intermediates` is passed (with no value, defaults here).

The `output/` tree is tracked in git; `.gitkeep` files keep
`output/runs/`, `output/reports/`, and `output/eval/` present.

---

## 13. Tests

82 tests across 11 test files (pre-custom-provider). After adding custom
provider support, the suite grew to 93 tests across the same 11 files:

| File | Tests | What it covers |
|---|---|---|
| `test_remediator.py` | 7 | KB loading, CVE lookup, service fallback, empty KB, remediation with/without RAG |
| `test_report_composer.py` | 6 | HTML renders, PDF generates, executive summary, bar widths scale with risk score, non-remediated render |
| `test_scorer_fewshot.py` | 4 | Few-shot/zero-shot response parsing, fallback label coercion |
| `test_evaluation.py` | 16 | Ground truth mapping, metric computation, Spearman, CVSS-only baseline, manual time estimate, full experiment grid |
| `test_pipeline_integration.py` | 2 | End-to-end pipeline (parse→enrich→score→prioritize→remediate→compose) with mock client, zero-shot+no-rag variant |
| `test_cli.py` | 26 | Help text, text/HTML/PDF/both reports, HTML without `--remediate`, zero-shot+no-rag, save-intermediates (explicit + default path), multi-input merge, `--local-only` (triage + eval), timestamped run dirs, eval timestamped output, evaluate single-model, error handling, custom provider validation (11 dedicated tests) |
| `test_pipeline.py` | 6 | Extracted `run_pipeline()`: HTML+PDF render, text-to-stdout, default intermediates dir, explicit intermediates dir, remediation on/off |
| `test_webapp.py` | 7 | Dashboard/forms render, new-run (sample + uploads) reaches `done`, stamp + Download PDF present, `--local-only` blocks cloud in the webapp, eval list |
| `test_scorer_ensemble.py` | 8 | Strict-majority merge (quorum met / not / even-N unanimity / explicit quorum), single-client path unchanged, ensemble resolve + Unresolved splits |
| `test_cli_ensemble.py` | 4 | `--ensemble`/`--quorum` parse, ensemble runs the pipeline and merges, invalid member rejected, `--local-only` blocks a cloud ensemble member |
| `test_webapp_models_ensemble.py` | 7 | `/models` route (list / unknown / best-effort on exception), `/runs/new` form has local-only above provider + datalist + ensemble toggle, ensemble POST records params, mismatched-length rejection, local-only blocks ensemble cloud member |
| `conftest.py` | — | `MockLLMClient` fixture (canned structured JSON responses) |

All tests use mock LLM responses — no real model needed; the webapp tests patch `run_pipeline` so no model is required either.

---

## 14. Dependencies

| Package | Version | Used by |
|---|---|---|
| `pydantic` | ≥2.0 | Data models |
| `openai` | ≥1.0 | LLM client |
| `pyyaml` | ≥6.0 | Asset registry parsing |
| `jinja2` | ≥3.0 | HTML template rendering |
| `weasyprint` | ≥62 | PDF generation |
| `scipy` | ≥1.11 | Spearman rank correlation |
| `pytest` / `pytest-cov` | — | Testing |
| `ruff` / `ty` | — | Linting / type checking |

---

## 15. Files Structure (Complete)

```
project/
├── main.py                          # Entry point → cli.main()
├── pyproject.toml                   # Dependencies
├── README.md                        # Updated with v2
├── .gitignore
├── .dockerignore
├── data/
│   ├── assets.yaml                  # Host→criticality (v1)
│   ├── synthetic_findings.json      # 20 findings with ground truth (v1 expanded)
│   ├── cve_kb.json                  # RAG knowledge base (v2)
│   ├── eval_config.example.json     # Experiment config template (v2)
│   ├── templates/
│   │   └── report.html              # Jinja2 HTML report template (v2)
│   ├── sample_nmap.xml              # Example Nmap input (v1)
│   ├── sample_nuclei.jsonl          # Example Nuclei input (v1)
│   ├── openvas_sample.csv           # Example OpenVAS CSV export (v5)
│   ├── nuclei_scan_*.jsonl          # Generated Nuclei scan outputs
│   └── nmap_scan_*.xml              # Generated Nmap scan outputs
├── src/vulntriage/
│   ├── __init__.py                  # Exports all models
│   ├── models.py                    # Pydantic data models (v1 + RemediatedFinding v2)
│   ├── llm.py                       # LLM client abstraction (v1; total_tokens v2; _provider_config + list_models + custom provider v3)
│   ├── parser.py                    # Scanner input parsers (v1 + OpenVAS CSV v5)
│   ├── scanner.py                   # Nuclei + Nmap runners — direct binary or Docker fallback (v1 + Docker v4 + Nmap v5)
│   ├── enricher.py                  # Context enrichment (v1)
│   ├── scorer.py                    # Exploitability scoring (v1, few_shot param v2, ensemble clients/quorum v3)
│   ├── prioritizer.py               # Risk prioritization (v1)
│   ├── reporter.py                  # Plain text report (v1)
│   ├── remediator.py                # Remediation with RAG (v2, new)
│   ├── report_composer.py           # HTML + PDF reports (v2, new)
│   ├── evaluation.py                # Experiment harness (v2, new)
│   ├── json_utils.py                # Shared JSON parsing helpers (v2, new)
│   ├── pipeline.py                  # Extracted triage run logic (shared by CLI + webapp)
│   ├── webapp/                      # FastAPI local web interface (v3, new)
│   │   ├── app.py                   # Routes, run registry, run worker wiring
│   │   ├── runs.py                  # In-memory RunRegistry + RunWorker + stdout capture
│   │   ├── templates/               # Jinja2 pages (Case File design system)
│   │   └── static/{style.css,app.js}#
│   └── cli.py                       # CLI orchestration (v1 + v2 + --web flags)
├── tests/
│   ├── conftest.py                  # MockLLMClient fixture
│   ├── test_remediator.py
│   ├── test_report_composer.py
│   ├── test_scorer_fewshot.py
│   ├── test_evaluation.py
│   ├── test_pipeline_integration.py
│   ├── test_cli.py
│   ├── test_pipeline.py             # run_pipeline() unit tests
│   ├── test_scorer_ensemble.py      # Ensemble merge + Unresolved (v3)
│   ├── test_cli_ensemble.py         # --ensemble / --quorum CLI (v3)
│   ├── test_webapp_models_ensemble.py # /models route + ensemble POST (v3)
│   └── test_webapp.py               # FastAPI TestClient webapp tests
├── docs/
│   ├── specs/
│   │   ├── triage-pipeline-design.md            # v1 design spec
│   │   ├── triage-pipeline-v2-design.md         # v2 design spec
│   │   ├── webapp-design.md                     # Webapp design spec
│   │   └── ensemble-and-model-picker-design.md  # Ensemble + /models + local-only reorder (v3)
│   └── plans/
│       └── triage-pipeline-v2-plan.md       # Implementation plan
├── output/                         # Tracked in git; run outputs never overwritten
│   ├── runs/<ts>/                  # Per-run HTML/PDF reports (timestamped)
│   ├── eval/<ts>/                  # Per-run eval metrics.json + results.csv (timestamped)
│   ├── reports/.gitkeep            # (legacy dir retained)
│   └── eval/.gitkeep
└── docker/
    ├── Dockerfile                   # Vulntriage image (v4, new)
    ├── compose.yaml                 # Vulntriage webapp (v4, new)
    ├── nuclei/
    │   └── Dockerfile               # Nuclei container (v1)
    ├── vuln-lab/
    │   └── compose.yaml             # Vulnerable targets
    └── openvas/
        └── compose.yaml             # Greenbone/OpenVAS
```

---

## 16. Known Limitations & Future Work

**Implemented in this iteration:**

- **Custom OpenAI-compatible provider** — `--provider custom --base-url <url>
  [--api-key <key>] [--local]` lets the pipeline target any
  OpenAI-compatible endpoint (local servers, proxies, niche cloud APIs)
  without a new entry in `_provider_config`. The `--local` flag gates it
  under `--local-only`; `--base-url` is mandatory. The webapp shows inline
  fields (base URL, API key, local checkbox) when `custom` is selected from
  the provider dropdown, and the model picker fetches from the custom
  endpoint's own `/models` route. 11 dedicated CLI tests cover every
  validation path.

- **Multiple scanner inputs at once** — `--input` accepts one or more files
  (XML/JSONL/JSON); findings are merged across all of them before triage.
- **`--local-only` mode** — the `LLMClient` carries a `local` flag
  (`True` for self-hosted providers); the CLI `--local-only` flag uses
  `LOCAL_PROVIDERS` (`lmstudio`/`ollama`/`llamacpp`/`vllm`) plus
  `--provider custom --local` to refuse cloud providers before any network
  call, in both triage and `--evaluate` modes (and across every `--ensemble`
  member).
- **Scan → triage in one command** — `--scan nuclei --target … --provider …
  --model …` (or `--scan nmap --target …`) runs the dockerized scanner and
  continues straight into triage; `--scan-only` skips triage.
- **Run outputs no longer overwritten** — triage reports go to
  `output/runs/<ts>/` and eval results to `output/eval/<ts>/` (timestamped);
  `--save-intermediates` (no value) defaults to `<run_dir>/intermediates/`.
- **Local-only above provider (webapp)** — the "Block cloud providers"
  checkbox renders above the provider `<select>` in both the triage and eval
  intake forms so it visually gates the provider list before the operator
  picks one.
- **Model picker from `/models`** — the model field is a `<datalist>`-backed
  `<input>` populated from the provider's OpenAI-compatible `/models` endpoint
  (best-effort; on failure it falls back to plain free text). A custom model
  name can always be typed, by the HTML primitive.
- **Multi-LLM ensemble (scoring only)** — `--ensemble` / `--quorum` and the
  webapp "Multi-LLM ensemble" toggle run the exploitability scorer against N
  models and merge by strict-majority quorum (default `⌊N/2⌋+1`); findings
  where no label reaches quorum are flagged `Unresolved`. See §6.1.

**Additional limitations relevant to the thesis evaluation:**

- **Ground truth is CVSS-E maturity, not expert labels** — `X`-maturity
  findings (9 of 20) are excluded from the accuracy metric but retained for
  ranking, where they use a manually-assigned `label`. The accuracy and
  ranking metrics therefore measure against different ground-truth sources;
  this is by design and should be stated explicitly in the methodology.
- **Small synthetic dataset (20 findings)** limits statistical weight; report
  mean ± std over the 3 repeats per cell.
- **No LLM response cache** — the 36-cell grid re-calls the model; a
disk cache keyed by `(model, prompt)` would cut cost and improve
  reproducibility for re-runs.
- **Temperature fixed at 0.2** — not configurable from the CLI; the v2 design
  flagged temp=0 for eval runs as a non-determinism mitigation.
- **Ensemble scope is scoring-only** — enrichment and remediation are
  deliberately not fanned out (merging prose is messy and doesn't directly
  address false positives); see `ensemble-and-model-picker-design.md` for the
  rationale. A whole-pipeline replication mode is left as future work.
- **`Unresolved` findings still get a risk score and rank** — the merge sets
  `exploitability` to the highest tally label so the deterministic prioritizer
  ranks an unresolved finding somewhere, which is a deliberate bias toward
  surfacing rather than hiding; the thesis should report the Unresolved count
  alongside the High/Medium/Low distribution so the reader sees how often the
  models disagreed.
- **`/models` is best-effort and provider-shape-dependent** — model id parsing
  tries `data[].id` then `body.model` then `model`; providers with unusual
  shapes may return an empty list (in which case the operator types the model
  name by hand). The route never blocks a run on a `/models` failure.
- **Ensemble inside `--evaluate` is out of scope** — the eval grid already
  varies models across cells, so ensemble-on-eval would double-count; the two
  features are kept independent.

---

## 17. Web Interface (`src/vulntriage/webapp/`)

A local browser UI (`uv run python main.py --web`, or
`uv run uvicorn vulntriage.webapp.app:app --reload`) presents each triage
pass and evaluation grid as a **case file** in an analyst's archive. It is a
thin viewer/controller over thesame filesystem run layout the CLI writes — no
database, no separate run model.

### 17.1 Routes

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Archive dashboard: recent triage + eval runs |
| `/runs` | GET | Triage run list |
| `/runs/new` | GET/POST | Intake form: upload files / use sample / scan a target; spawns a worker |
| `/runs/<id>` | GET | Run dossier: stamped manifest + live progress + embedded report |
| `/runs/<id>/status` | GET | JSON: state, progress tail, counts, artifact flags (polled by `app.js`) |
| `/runs/<id>/report.html` | GET | The rendered HTML report (served from disk) |
| `/runs/<id>/report.pdf` | GET | The PDF report, as a download (`application/pdf`) |
| `/runs/<id>/download` | GET | Intermediates as a zip |
| `/models?provider=<name>` | GET | Best-effort model list for the picker: `{"models": [...], "error": null\|str}` |
| `/eval`, `/eval/new`, `/eval/<id>` | GET/POST | Evaluation grid launch + dossier + metrics table |

### 17.2 Run model

A run is a timestamped directory under `output/runs/` (triage) or
`output/eval/` (eval). The webapp holds only in-flight runs in an in-memory
`RunRegistry`; the filesystem stays the source of truth. On startup
`recover_interrupted()` scans the run dirs and marks any lacking a final
artifact (`report.html`/`report.pdf` for triage, `metrics.json` for eval) —
and not live — as `interrupted`, so a server restart never hides a
half-finished run.

Each run executes in a `RunWorker` thread. The pipeline's existing `print()`
lines are captured by a per-worker `sys.stdout` redirect into a ring buffer,
which becomes the live progress feed — no instrumentation of the pipeline
itself. The webapp calls the same `vulntriage.pipeline.run_pipeline` (and
`vulntriage.evaluation.run_experiment`) the CLI uses, so behaviour is
identical.

### 17.3 Intake form: provider/model picker, local-only, ensemble

The intake form (`/runs/new`, mirrored at `/eval/new` for the eval grid)
orders the controls so the gate comes first and the suggestions follow:

1. **Local-only** checkbox sits **above** the provider `<select>` so it
   visually gates the provider list before the operator picks one. Toggling it
   hides non-local `<option>`s and auto-switches to the first local provider,
   refreshing the model datalist in the same handler.
2. **Provider** `<select>` and **Model** `<input list="models-dl">` — the
   `<datalist>` is repopulated from `/models` on every provider change.
   `<datalist>` is pure suggestion, so a custom model name can always be typed;
   on `/models` failure the datalist is emptied and free text remains.
3. **Multi-LLM ensemble (scoring only)** checkbox reveals an "Add scoring
   model" section that appends extra (provider, model) rows reusing the same
   datalist, plus a **Quorum** field (default `⌊N/2⌋+1`, editable). The
   primary provider/model above is the first ensemble member and is used for
   enrichment + remediation. Unchecking the toggle clears the extra rows so
   the submission is identical to a single-model POST.

`POST /runs/new` accepts repeated `ensemble_provider[]`/`ensemble_model[]`
fields plus `quorum`; the worker builds N scoring clients and one primary
client, and stores `ensemble` + `quorum` under `RunRecord.params`. The dossier
manifest shows an "Ensemble (scoring)" field with the member list and quorum
when set, and the counts row adds an `Unresolved` total.

### 17.4 PDF download

Every web-driven triage run renders **both** `report.html` (shown in an
`<iframe>` on the dossier) and `report.pdf` (the Download PDF button)
regardless of the `--remediate` toggle, so the file offered for download is
byte-identical to what `--output-format both` would produce from the CLI.

### 17.5 Design — "Case File"

The UI treats each run as a physical case file: a paper-buff folder with
pre-printed form boxes and a rubber-stamp status mark. The signature element
is the stamp (REVIEWED / IN REVIEW / FAILED / HALTED) — rotated –6° in
oxblood with a distressed SVG-filter edge; the only animation is a 200 ms
"landing" on transition to done (disabled under `prefers-reduced-motion`).

Type: *Spectral* (display serif), *IBM Plex Sans* (body), *JetBrains Mono*
(run IDs, host:port, CVSS). Palette: `paper #EFEADF`, `ink #1F1E1B`,
`oxblood #7A2F26`, `ochre #9A6B1A`, `sage #5C6E4B`, `hairline #C5BEAD`.
Everything else is disciplined: hairline rules, ~no radii, no shadows, no
gradients; severity colour comes only from the data.

---

## 18. Docker Support

The full pipeline (CLI + webapp) ships as a single Docker image with Nuclei
pre-installed as a native Linux binary — no separate Nuclei container, no
Docker socket mount, no Docker-in-Docker.

### 18.1 Motivation

The original scanner module (`scanner.py`) ran Nuclei exclusively through
``docker run`` against a local image built from `docker/nuclei/Dockerfile`.
Nmap support was added later (v5), following the same pattern: a
`docker/nmap/Dockerfile` that produces a minimal Alpine-based image, and
`run_nmap()` mirroring the `run_nuclei()` interface (binary detection +
Docker fallback).
Dockerizing the pipeline itself would have required either Docker-in-Docker
(privileged mode, not recommended) or mounting the host Docker socket
(Docker-outside-of-Docker, which introduces volume-path mapping issues and
socket permission headaches).

The chosen approach sidesteps both: the vulntriage image bundles the Nuclei
binary directly, copied from the official `projectdiscovery/nuclei:v3` image
via a multi-stage build, with templates pre-downloaded at build time
(`nuclei -ut`). When the image runs attached to ``vuln-net`` (the same
external Docker network used by the vulnerable-lab targets), Docker's
embedded DNS resolves container names like ``dvwa`` natively — no manual
hostname-to-IP resolution is needed.

### 18.2 Binary detection in `scanner.py`

`run_nuclei()` checks ``shutil.which("nuclei")`` at runtime:

- **Binary found** → ``subprocess.run(["nuclei", "-u", target_list, ...])`` is
  called directly (for nmap: ``["nmap", "-oX", "-", target_list]``). No
  Docker networking flags, no volume mounts, no ``docker inspect`` hostname
  resolution — DNS works natively on `vuln-net`.
- **Binary not found** → the existing ``docker run my-nuclei`` (or
  ``my-nmap``) fallback is used unchanged, preserving the original host-based
  workflow.

This means the same code works both inside the Docker image (where nuclei and
nmap are on ``$PATH``) and on a developer host with only the scanner Docker
images available.

### 18.3 Image structure

The Dockerfile (`docker/Dockerfile`) uses three build stages:

| Stage | Source | Purpose |
|---|---|---|
| `nuclei-src` | `projectdiscovery/nuclei:v3` | Nuclei binary |
| `uv-bin` | `ghcr.io/astral-sh/uv:latest` | uv package manager |
| runtime | `python:3.14-slim` | Final image |

System dependencies for WeasyPrint (PDF rendering) are installed via `apt`.
Application dependencies are installed with ``uv sync --frozen --no-dev``;
the entrypoint is ``uv run python main.py`` with ``--help`` as the default
command.

### 18.4 Usage

**One-shot CLI scan + triage:**
```bash
docker build -f docker/Dockerfile -t vulntriage .
docker network create -d bridge vuln-net  # first time only
# Nuclei scan
docker run --network vuln-net -v ./output:/app/output vulntriage \
    --scan nuclei --target dvwa \
    --provider lmstudio --model qwen3.5-4b \
    --output-format both --remediate
# Nmap scan
docker run --network vuln-net -v ./output:/app/output vulntriage \
    --scan nmap --target 192.168.1.0/24 \
    --provider lmstudio --model qwen3.5-4b
```

**Persistent webapp + targets:**
```bash
docker compose -f docker/vuln-lab/compose.yaml up -d  # targets
docker compose -f docker/compose.yaml up --build       # webapp on :9000
```

The compose file (`docker/compose.yaml`) attaches the webapp to the external
`vuln-net` network and bind-mounts `./output` so reports survive container
recreation. The webapp writes to the same `output/runs/<ts>/` layout as the
CLI, and a ``docker compose down`` + ``up`` recovers interrupted runs from
disk.

### 18.5 Files

| File | Purpose |
|---|---|
| `docker/Dockerfile` | Multi-stage vulntriage image |
| `docker/compose.yaml` | Webapp service + network wiring |
| `.dockerignore` | Excludes venv, git, caches, tests from build context |
| `src/vulntriage/scanner.py` | Updated with binary detection + fallback (nuclei + nmap) |

The existing `docker/nuclei/Dockerfile` and `docker/nmap/Dockerfile`
(standalone scanner containers) are preserved — they remain the fallback used
when running on a host without a local scanner installation.