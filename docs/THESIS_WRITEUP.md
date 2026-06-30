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
Scanner output (Nmap XML / Nuclei JSONL / synthetic JSON)
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
| `ScoredFinding` | `EnrichedFinding` | `exploitability` (High/Medium/Low enum), `exploitability_rationale`, `scoring_model` | Scorer output |
| `PrioritizedFinding` | `ScoredFinding` | `asset_criticality` (float), `risk_score`, `rank` | Prioritizer output |
| `RemediatedFinding` | `PrioritizedFinding` | `remediation_steps` (list[str]), `remediation_rationale`, `rag_hits`, `remediation_model` | Remediator output |

`Exploitability` is a `StrEnum` with values `HIGH`, `MEDIUM`, `LOW` and a
`.numeric()` method returning 1.0, 0.5, 0.1 respectively — used by the
prioritizer formula.

---

## 3. LLM Client (`llm.py`)

**`LLMClient`** is a Protocol (structural interface) requiring:
- `model: str`
- `total_tokens: int` (best-effort accumulator)
- `complete(system: str, user: str) -> str`

**`OpenAICompatibleClient`** is the real implementation. It wraps the OpenAI
SDK and supports six providers via `make_client()` factory:
- `lmstudio` — local, base URL `http://localhost:1234/v1`
- `ollama` — local, `http://localhost:11434/v1`
- `llamacpp` / `vllm` — local alternatives
- `openai` — cloud, requires `OPENAI_API_KEY`
- `openrouter` — cloud, requires `OPENROUTER_API_KEY`

Each provider can be configured with `--reasoning-effort low|medium|high` for
models that support chain-of-thought reasoning. Temperature is fixed at 0.2
for reproducibility. Token usage is captured from API response metadata when
available.

---

## 4. Parser (`parser.py`)

Auto-detects format from file extension:

| Extension | Format | Parser | Key implementation |
|---|---|---|---|
| `.xml` | Nmap XML | `xml.etree.ElementTree` | Iterates `<port>` elements with state="open", extracts service + product + version |
| `.jsonl` | Nuclei JSONL | Line-by-line `json.loads` | Extracts template-id, name, severity, CVSS score, CVE-ID from the classification block |
| `.json` | Synthetic | `json.loads` | Reads array of items with our schema (used for test data) |

All parsers normalize to `list[RawFinding]`. Findings get unique IDs prefixed
by source (`nmap-…`, `nuclei-…`, `synthetic-…`).

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
2. **Risk Breakdown** — horizontal bar chart per finding (CSS bars styled by
   exploitability color: red/orange/green)
3. **Technical Findings** — per-finding card with host, port, CVE, CVSS, risk
   score, context, exploitability rationale, remediation steps with rationale,
   RAG references
4. **Ranked Summary Table** — all findings in a table (Rank, Score,
   Exploitability, Finding, Host)

WeasyPrint converts the HTML to PDF. Both formats share the same template;
output is controlled by `--output-format` (text|html|pdf|both).

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

Outputs: `output/eval/metrics.json` (per-cell mean + std for each metric) and
`output/eval/results.csv` (one row per run, 36 + 2 baseline rows).

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
| `--input` | v1 | Path to scanner output (XML/JSONL/JSON) |
| `--scan` | v1 | Run dockerized Nuclei scanner |
| `--target` | v1 | Target for `--scan` |
| `--provider` | v1 | LLM provider (lmstudio/ollama/openai/openrouter/…) |
| `--model` | v1 | Model name |
| `--reasoning-effort` | v1 | Thinking level for reasoning models |
| `--asset-registry` | v1 | YAML file with host→criticality |
| `--output` | v1 | Output path / directory |
| `--output-format` | v2 | text/html/pdf/both |
| `--remediate` | v2 | Run remediation generator |
| `--rag` / `--no-rag` | v2 | Toggle RAG grounding |
| `--kb` | v2 | Path to RAG knowledge base |
| `--prompt-strategy` | v2 | few-shot (default) / zero-shot |
| `--evaluate` | v2 | Run the evaluation experiment grid |
| `--eval-config` | v2 | JSON config file for multi-model grid |
| `--repeats` | v2 | Repeats per condition in eval mode |
| `--save-intermediates` | v2 | Dump intermediate pipeline outputs |
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
breakdown bars, per-finding cards with remediation, ranked table.

---

## 13. Tests

40 tests across 7 test files:

| File | Tests | What it covers |
|---|---|---|
| `test_remediator.py` | 6 | KB loading, CVE lookup, service fallback, empty KB, remediation with/without RAG |
| `test_report_composer.py` | 4 | HTML renders, PDF generates, executive summary written, findings in output |
| `test_scorer_fewshot.py` | 4 | Few-shot/zero-shot response parsing, fallback label coercion |
| `test_evaluation.py` | 7 | Ground truth mapping, metric computation, Spearman, CVSS-only baseline, manual time estimate, full experiment grid |
| `test_pipeline_integration.py` | 2 | End-to-end pipeline (parse→enrich→score→prioritize→remediate→compose) with mock client, zero-shot+no-rag variant |
| `test_cli.py` | 7 | Help text, text/HTML/PDF/both reports, zero-shot+no-rag, save-intermediates, evaluate single-model, error handling |
| `conftest.py` | — | `MockLLMClient` fixture (canned structured JSON responses) |

All tests use mock LLM responses — no real model needed. Coverage: report_composer 100%, remediator 96%, evaluation 85%, cli 83%, models 100%, scorer 79%.

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
├── data/
│   ├── assets.yaml                  # Host→criticality (v1)
│   ├── synthetic_findings.json      # 20 findings with ground truth (v1 expanded)
│   ├── cve_kb.json                  # RAG knowledge base (v2)
│   ├── eval_config.example.json     # Experiment config template (v2)
│   ├── templates/
│   │   └── report.html              # Jinja2 HTML report template (v2)
│   ├── sample_nmap.xml              # Example Nmap input (v1)
│   ├── sample_nuclei.jsonl          # Example Nuclei input (v1)
│   └── nuclei_scan_*.jsonl          # Generated scan outputs
├── src/vulntriage/
│   ├── __init__.py                  # Exports all models
│   ├── models.py                    # Pydantic data models (v1 + RemediatedFinding v2)
│   ├── llm.py                       # LLM client abstraction (v1, total_tokens v2)
│   ├── parser.py                    # Scanner input parsers (v1)
│   ├── scanner.py                   # Dockerized Nuclei runner (v1)
│   ├── enricher.py                  # Context enrichment (v1)
│   ├── scorer.py                    # Exploitability scoring (v1, few_shot param v2)
│   ├── prioritizer.py               # Risk prioritization (v1)
│   ├── reporter.py                  # Plain text report (v1)
│   ├── remediator.py                # Remediation with RAG (v2, new)
│   ├── report_composer.py           # HTML + PDF reports (v2, new)
│   ├── evaluation.py                # Experiment harness (v2, new)
│   ├── json_utils.py                # Shared JSON parsing helpers (v2, new)
│   └── cli.py                       # CLI orchestration (v1 + v2 flags)
├── tests/
│   ├── conftest.py                  # MockLLMClient fixture
│   ├── test_remediator.py
│   ├── test_report_composer.py
│   ├── test_scorer_fewshot.py
│   ├── test_evaluation.py
│   ├── test_pipeline_integration.py
│   └── test_cli.py
├── docs/
│   ├── specs/
│   │   ├── 2026-06-26-triage-pipeline-design.md  # v1 design spec
│   │   └── 2026-06-30-triage-pipeline-v2-design.md  # v2 design spec
│   └── plans/
│       └── 2026-06-30-triage-pipeline-v2-plan.md  # Implementation plan
├── output/
│   ├── eval/                        # Experiment results (metrics.json, results.csv)
│   └── reports/                     # Generated reports (report.html, report.pdf)
└── docker/nuclei/
    └── Dockerfile                   # Nuclei container (v1)
```