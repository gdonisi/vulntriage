# Design: LLM-Enabled Vulnerability Triage Pipeline (v2)

## Goal

Complete the pipeline with remediation generation and polished reporting. Build a
structured experiment framework that systematically varies models, prompting
strategies, and RAG conditions to produce thesis-ready tables and charts. The
evaluation answers the thesis question quantitatively:

> *"Can an LLM-driven vulnerability triage pipeline improve exploitability
> scoring accuracy against a CVSS-based baseline and reduce triage time relative
> to estimated manual review?"*

**Measured outputs:**

- Exploitability label accuracy (precision, recall, F1) vs CVSS exploit maturity
  ground truth
- Ranking correlation (how well LLM-enriched risk scores match expert-informed
  ordering vs CVSS-only ordering)
- Wall-clock pipeline latency vs estimated manual analyst effort
- Ablation results showing which components (RAG, few-shot prompting) contribute
  most to accuracy

## Thesis Question (carried from v1)

> Can an LLM-driven vulnerability triage pipeline improve both exploitability
> scoring accuracy against human expert labels and triage throughput over raw
> CVSS-based prioritization?

v2 narrows the ground truth from "human expert labels" to a CVSS exploit
maturity proxy (see Assumptions) for practical reproducibility, while keeping
the same two dimensions: accuracy and throughput.

## Assumptions

1. **Ground truth labels** come from CVSS temporal exploit maturity metrics
   (E scores and exploit availability from NVD) — treated as a proxy for human
   expert labels.
2. **Existing synthetic findings** (`data/synthetic_findings.json`) get expanded
   with ground-truth exploitability labels and remediation references for eval.
3. **RAG knowledge base** is a static curated JSON file covering the top CVEs
   and service classes in the synthetic dataset — no live NVD API calls during
   pipeline runs.
4. **Remediation module** uses the same LLM abstraction as enricher/scorer —
   injected at construction, provider-swappable.
5. **Final Report Composer** uses Jinja2 for HTML and WeasyPrint for PDF —
   single HTML template, converted to PDF. Content: executive summary, risk
   breakdown, per-finding detail with remediation, ranked table.
6. **Experiment framework** is a separate CLI entrypoint that runs the pipeline
   under multiple conditions, captures latency/tokens/outputs, and computes
   metrics — no real-time dashboard, just JSON/CSV outputs for thesis analysis.
7. **Manual analyst effort estimates** are modeled as time-per-finding based on
   published security triage studies — not measured live. Pipeline time is
   measured via `time.perf_counter()` (already logged in v1).
8. **Existing pipeline modules stay behavior-compatible** — v2 adds new
   modules and an eval harness. The v1 core (parser, enricher, scorer,
   prioritizer, reporter) is not rewritten. The only additive change is that
   the scorer gains an optional `few_shot: bool = True` parameter so the
   experiment can toggle zero-shot vs few-shot prompting; the default
   preserves v1 behavior.
9. **CLI remains a single entry point** — new features are exposed via
   additional flags (`--remediate`, `--output-format html|pdf`, `--evaluate`),
   not a separate command.

## Unknowns / Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| CVSS exploit maturity as ground truth is noisy — not all CVEs have E scores, and the metric doesn't always match real-world exploitability | Medium | Report this limitation in the thesis, treat E-score correlation as a lower-bound estimate of accuracy, supplement with manual spot-checks |
| Small synthetic dataset (5 findings) limits statistical weight of the evaluation | High | Expand to at least 15-20 synthetic findings covering diverse services, exposure levels, and CVE/no-CVE cases before running experiments |
| RAG knowledge base maintenance — if curated by hand, may be incomplete or biased toward the synthetic test set | Medium | Structure the KB as a JSON schema that's easy to extend; document coverage gaps in thesis limitations |
| WeasyPrint rendering quirks — complex HTML/CSS may not render identically in PDF | Low | Keep the report template simple (tables, sections, no fancy CSS); test early |
| LLM non-determinism — same finding may get different exploitability labels across runs, making accuracy numbers unstable | Medium | Run each experiment condition 3+ times and report mean + variance; use temperature=0.2 (already in v1); consider temperature=0 for eval runs |
| OpenRouter costs — running multiple conditions × 3 runs × 20 findings could add up with paid models | Medium | Run paid-model conditions last, with a token budget cap; emphasize free models (DeepSeek on OpenRouter) for most runs |
| Experiment framework scope creep — too many dimensions (models × prompts × RAG × temperature) explodes combinatorially | High | Limit to 3 models (1 local small, 1 local medium, 1 cloud), 2 prompt strategies (zero-shot, few-shot), 2 RAG conditions (on/off). That's 12 conditions — manageable |
| Remediation quality is hard to measure — no ground truth for "good" fix suggestions | Low | Remediation is evaluated qualitatively in the thesis (review a sample, note common patterns/hallucinations); no quantitative metric claimed |

## Proposed Approach

**Modular addition to the existing v1 pipeline.** No refactoring. Every new
module receives typed Pydantic models and optional LLM injection, following the
same pattern as v1.

### New Modules in v2

| # | Module | Input | Output | LLM? |
|---|--------|-------|--------|------|
| 6 | **Remediator** | `PrioritizedFinding` + RAG KB | `RemediatedFinding` | Yes |
| 7 | **Report Composer** | `List[RemediatedFinding]` | HTML string + PDF file | No |
| — | **Eval Harness** | Pipeline intermediates + ground truth | JSON metrics, CSV tables | No |

### RAG Strategy

Before each remediation LLM call, the module looks up the finding's CVE and
service in a local JSON knowledge base. If hits exist, the relevant mitigations
are injected into the prompt as context. If not, the LLM generates from its own
knowledge. This keeps the RAG simple, offline, and reproducible.

### Experiment Design

**3 models × 2 prompt strategies × 2 RAG conditions = 12 cells.** Each cell
runs 3 times. Metrics per run:

1. **Accuracy**: precision/recall/F1 of exploitability labels vs CVSS-E ground
   truth
2. **Ranking quality**: Spearman rank correlation of pipeline ordering vs
   ground-truth ordering
3. **Latency**: per-module and end-to-end wall-clock time
4. **Token usage**: total tokens consumed (proxy for cost)

**Ground truth label mapping.** CVSS temporal exploit maturity (E) values
map to the pipeline's three-tier labels as follows:

| CVSS-E value | Meaning | Ground-truth label |
|---|---|---|
| X (Not Defined) | no temporal data | excluded from accuracy metric |
| H (High) | functional exploit available | High |
| F (Functional) | functional exploit available | High |
| P (Proof-of-Concept) | PoC code available | Medium |
| U (Unproven) | no exploit available | Low |

Findings with no CVE (and therefore no E score) are excluded from the
accuracy metric but retained for the ranking and latency metrics.

**Baselines for comparison:**

- **CVSS-only prioritization**: rank by CVSS base score, ignore LLM enrichment
- **Manual triage estimate**: modeled time-per-finding from published security
  triage studies (cited in the thesis); used only as a throughput reference,
  not an accuracy reference

### Report Composer Flow

```
PrioritizedFinding → RemediatedFinding →
  Jinja2 HTML template →
    → HTML file (browser-viewable)
    → WeasyPrint → PDF file (print-ready)
```

Single template with: executive summary, risk bar chart (ASCII or simple CSS
bars), per-finding sections with remediation, ranked summary table.

### Data Flow (v2 full pipeline)

```
Scanner Output
  → Parser          → List[RawFinding]
  → Enricher (LLM)  → List[EnrichedFinding]
  → Scorer (LLM)    → List[ScoredFinding]
  → Prioritizer     → List[PrioritizedFinding]
  → Remediator (LLM + RAG KB) → List[RemediatedFinding]
  → Report Composer → HTML + PDF
```

The eval harness intercepts after Scorer and after Prioritizer (not inline),
producing metrics from saved intermediates.

## Step-by-Step Plan

1. **Expand the synthetic dataset** — grow `data/synthetic_findings.json` from 5
   to ~20 findings spanning diverse services (Redis, SSH, Tomcat, MySQL, nginx,
   + new: Jenkins, Elasticsearch, MongoDB, Grafana, Postgres, etc.), varied
   exposure (internet-facing vs internal), and CVE/no-CVE cases. Add a
   `ground_truth` field with exploitability label + CVSS-E maturity to each.
2. **Build the RAG knowledge base** — create `data/cve_kb.json`, a curated
   mapping of CVE/service → mitigation steps for the top CVEs represented in the
   synthetic dataset. Schema: `{cve, service, summary, remediation_steps[]}`.
3. **Add `RemediatedFinding` model** — extend `models.py` with a
   `RemediatedFinding(PrioritizedFinding)` carrying `remediation_steps:
   list[str]`, `remediation_rationale`, `rag_hits: list[str]`,
   `remediation_model`.
4. **Build the Remediator** (`remediator.py`) — lookup CVE/service in
   `cve_kb.json`, inject hits into the LLM prompt, parse structured JSON steps
   into `RemediatedFinding`. RAG on/off toggle.
5. **Build the Report Composer** (`report_composer.py`) — Jinja2 HTML template
   (`data/templates/report.html`) producing executive summary, risk breakdown,
   per-finding detail with remediation, ranked table. WeasyPrint renders HTML →
   PDF. Outputs both formats.
6. **Build the Eval Harness** (`evaluation.py`) — separate CLI path
   (`--evaluate`) that runs the pipeline under all 12 conditions, computes
   precision/recall/F1 vs ground truth, Spearman rank correlation, latency,
   token usage. Writes `output/eval/metrics.json` and
   `output/eval/results.csv`.
7. **Add baselines to the eval harness** — CVSS-only prioritization ranking +
   manual-triage time model, both compared against pipeline outputs in the same
   metrics file.
8. **Extend the scorer for prompt strategies** — add an optional
   `few_shot: bool = True` parameter to `score()`/`score_all()`; when `False`,
   the few-shot examples are omitted from the prompt (zero-shot). Default stays
   `True` to preserve v1 behavior.
9. **Extend the CLI** — add `--remediate`, `--output-format html|pdf|both`,
   `--rag/--no-rag`, `--prompt-strategy few-shot|zero-shot`, `--evaluate` flags.
   Wire remediator + report composer into the main pipeline flow.
10. **Add dependencies** — `jinja2`, `weasyprint`, `scipy` to `pyproject.toml`.
11. **Write tests** — unit tests for remediator (with/without RAG hits), report
    composer (template renders, PDF generates), eval harness (metric
    computation on a tiny known dataset).
12. **Run the full experiment** — execute all 12 conditions × 3 runs on the
    expanded dataset, capture metrics, verify charts/tables generate.
13. **Update README** — document v2 modules, new CLI flags, eval workflow, and
    how to reproduce experiments.

## Files / Areas Likely Affected

```
src/vulntriage/
  models.py            # ADD: RemediatedFinding model
  remediator.py        # NEW: remediation with light RAG
  report_composer.py   # NEW: HTML (Jinja2) + PDF (WeasyPrint)
  evaluation.py        # NEW: experiment harness + metrics
  scorer.py            # MODIFY: add few_shot parameter (default preserves v1)
  cli.py               # MODIFY: new flags, wire new modules
  __init__.py          # MODIFY: export new modules

data/
  synthetic_findings.json   # MODIFY: expand to ~20, add ground_truth
  cve_kb.json               # NEW: curated RAG knowledge base
  templates/
    report.html             # NEW: Jinja2 report template
  ground_truth.csv          # NEW: extracted labels for eval (optional)

output/
  eval/
    metrics.json            # NEW: experiment metrics
    results.csv             # NEW: per-condition results table
  reports/
    report.html             # NEW: generated reports
    report.pdf

tests/
  test_remediator.py        # NEW
  test_report_composer.py   # NEW
  test_evaluation.py        # NEW

pyproject.toml              # MODIFY: add jinja2, weasyprint, scipy
README.md                   # MODIFY: document v2
docs/specs/
  2026-06-30-triage-pipeline-v2-design.md  # NEW: this design doc
```

## Validation

- **Smoke test**: `uv run python main.py --input data/synthetic_findings.json
  --provider lmstudio --model <m> --remediate --output-format both` produces
  both `report.html` and `report.pdf` with remediation steps for each finding.
- **RAG toggle**: Run with `--rag` and `--no-rag` on a finding whose CVE is in
  the KB; confirm `--rag` injects KB content and `--no-rag` falls back to
  LLM-only.
- **Provider swap**: Same command with `--provider openrouter --model <m>`
  works identically.
- **Eval harness**: `uv run python main.py --evaluate --provider lmstudio
  --model <m>` runs all conditions, writes `metrics.json` and `results.csv`, and
  the CSV has 12 condition rows × 3 runs.
- **Baseline comparison**: Metrics file includes CVSS-only and manual-triage
  baseline rows alongside pipeline rows.
- **Report inspection**: Open `report.pdf` — executive summary, risk breakdown,
  per-finding remediation, and ranked table all render correctly.
- **Tests**: `uv run pytest` passes, including RAG-hit/no-hit branches and
  metric computation on a 3-finding known dataset.
- **Reproducibility**: `uv sync && uv run python main.py --help` works from a
  fresh clone; eval can be re-run and produces consistent metrics (within
  variance).
