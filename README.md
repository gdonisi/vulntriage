# LLM-Enabled Vulnerability Investigation and Triaging System

An AI-driven vulnerability triage pipeline. It ingests scanner results, enriches each finding with LLM-generated threat context, scores exploitability (High/Medium/Low), prioritizes by composite risk, generates LLM remediation recommendations (optionally grounded by a light RAG knowledge base), and produces ranked HTML/PDF reports. A built-in evaluation harness runs an experiment grid to measure accuracy and throughput for the thesis.

## Thesis Question

> Can an LLM-driven vulnerability triage pipeline improve both exploitability scoring accuracy against a CVSS-based baseline and triage throughput over estimated manual review?

## Quick start

```bash
uv sync

# v2: triage + remediation + HTML/PDF report with a local LM Studio model
uv run python main.py --input data/synthetic_findings.json \
    --provider lmstudio --model qwen3.5-4b \
    --asset-registry data/assets.yaml \
    --remediate --output-format both

# Merge findings from multiple scanner outputs at once
uv run python main.py --input data/sample_nmap.xml data/sample_nuclei.jsonl \
    --provider lmstudio --model qwen3.5-4b --remediate --output-format both

# v1-style plain-text report (no remediation)
uv run python main.py --input data/synthetic_findings.json \
    --provider lmstudio --model qwen3.5-4b \
    --asset-registry data/assets.yaml

# Block cloud providers (only self-hosted backends)
uv run python main.py --input data/synthetic_findings.json \
    --provider lmstudio --model qwen3.5-4b --local-only

# Using Nuclei JSONL output
uv run python main.py --input data/sample_nuclei.jsonl \
    --provider lmstudio --model qwen3.5-4b

# Using OpenRouter
OPENROUTER_API_KEY=sk-... uv run python main.py --input data/synthetic_findings.json \
    --provider openrouter --model deepseek/deepseek-v4-flash --remediate

# Using OpenAI API Platform with thinking on
OPENAI_API_KEY=sk-... uv run python main.py --input data/synthetic_findings.json \
    --provider openai --model gpt-5.4-nano --reasoning-effort high

# Multi-LLM ensemble (scoring only): the primary runs enrichment + remediation,
# and N models score each finding's exploitability; labels merge by strict-
# majority quorum (default floor(N/2)+1) to reduce false positives. Findings
# where no label reaches quorum are flagged Unresolved.
uv run python main.py --input data/synthetic_findings.json \
    --provider lmstudio --model qwen3.5-4b \
    --ensemble ollama:llama3.1,openai:gpt-4o-mini --quorum 2 --remediate

# Disable RAG / use zero-shot prompting
uv run python main.py --input data/synthetic_findings.json \
    --provider lmstudio --model qwen3.5-4b --remediate --no-rag \
    --prompt-strategy zero-shot

# Run the dockerized Nuclei scanner, then continue straight into triage
# (--scan-only would stop after the scan and save the JSONL)
docker network create -d bridge vuln-net
docker build -t my-nuclei:latest docker/nuclei
uv run python main.py --scan nuclei --target 192.168.1.5 \
    --provider lmstudio --model qwen3.5-4b

# Only run the Nuclei scan, save output and exit
uv run python main.py --scan nuclei --target 192.168.1.5 --scan-only
```

## Output layout

Each triage run writes to its own timestamped directory so previous results
are never overwritten:

- `output/runs/<YYYYMMDD-HHMMSS>/report.html`, `report.pdf` — HTML/PDF
  reports (text still goes to stdout unless `--output` is a file). Pass
  `--output <dir>` to choose a specific run directory instead.
- `output/eval/<YYYYMMDD-HHMMSS>/metrics.json`, `results.csv` — experiment
  grid outputs. Pass `--output <dir>` (or `output_dir` in the eval config) to
  override.
- `--save-intermediates` (with no value) dumps the enriched/scored/
  prioritized/remediated JSON to `<run_dir>/intermediates/`.

The `output/` tree is tracked in git; `.gitkeep` files keep the
`output/runs/`, `output/reports/`, and `output/eval/` directories present.

## Web interface

A local browser UI presents each triage pass and evaluation grid as a "case
file" — a stamped manifest, a live progress log while the LLM works, and the
rendered report embedded with a **Download PDF** control.

```bash
uv run python main.py --web
# or: uv run uvicorn vulntriage.webapp.app:app --reload
```

Open <http://127.0.0.1:9000>. From the dashboard you can:

- **Start a triage run** — upload one or more scanner outputs (or use the
  bundled sample dataset), pick a provider/model, toggle remediation/RAG, or
  run a Nuclei scan against a target and continue straight into triage. The
  model field is backed by a `/models` datalist fetched from the provider's
  OpenAI-compatible `/models` endpoint (best-effort; a custom model name can
  always be typed). The **Local only** checkbox sits above the provider rows
  and gates them. Tick **Multi-LLM ensemble (scoring only)** to score each
  finding with N models and merge by strict-majority quorum (findings where
  no label reaches quorum are flagged Unresolved).
- **Read the dossier** — the run's stamped status mark, a pre-printed manifest
  (provider, model, inputs, finding counts), the live progress log while
  running, and the embedded report once done.
- **Download the PDF** — every web-driven run renders both `report.html`
  (shown in the page) and `report.pdf` (the download button) to the run
  directory, so the in-app artifact and the file on disk are identical.
- **Run the evaluation grid** — `Evaluation › New` runs the 12-cell grid and
  renders `metrics.json` as a per-condition table.

The webapp reuses the exact same pipeline as the CLI (`vulntriage.pipeline`),
the same run layout under `output/runs/<id>/` and `output/eval/<id>/`, and
the same `--local-only` gate. Runs created from the CLI appear in the webapp
and vice versa; a server restart recovers interrupted runs from disk.

See `docs/specs/webapp-design.md` for the design and `docs/specs/ensemble-and-model-picker-design.md` for the ensemble / model-picker / local-only changes.

## Evaluation harness

Run the experiment grid (models × prompt strategies × RAG on/off) and write
`output/eval/metrics.json` + `output/eval/results.csv`:

```bash
# Single-model grid (1 model × 2 strategies × 2 RAG × 3 repeats)
uv run python main.py --evaluate --input data/synthetic_findings.json \
    --provider lmstudio --model qwen3.5-4b

# Full multi-model grid from a config file (copy and edit the example)
cp data/eval_config.example.json data/eval_config.json
uv run python main.py --evaluate --eval-config data/eval_config.json
```

Metrics per run: precision / recall / F1 of exploitability labels vs CVSS
exploit-maturity ground truth, Spearman rank correlation of the pipeline
ordering (and a CVSS-only baseline) vs the ground-truth ordering, pipeline
wall-clock latency, modelled manual-triage time, and token usage.

## Pipeline (v2)

```
Scanner output (Nmap XML / Nuclei JSONL / synthetic JSON)
  -> Parser (1+ files)    -> List[RawFinding]   # findings merged across inputs
  -> Context Enricher    (LLM)         -> List[EnrichedFinding]
  -> Exploitability Scorer (LLM)       -> List[ScoredFinding]
  -> Prioritizer         (formula)     -> List[PrioritizedFinding]
  -> Remediator          (LLM + RAG)   -> List[RemediatedFinding]
  -> Report Composer     (Jinja2/PDF)  -> HTML + PDF report
```

## Modules

| Module | File | Input -> Output |
|---|---|---|
| Parser | `src/vulntriage/parser.py` | scanner file -> `List[RawFinding]` |
| Nuclei runner | `src/vulntriage/scanner.py` | docker image -> JSONL file |
| Context Enricher | `src/vulntriage/enricher.py` | `RawFinding` -> `EnrichedFinding` |
| Exploitability Scorer | `src/vulntriage/scorer.py` | `EnrichedFinding` -> `ScoredFinding` |
| Prioritizer | `src/vulntriage/prioritizer.py` | `ScoredFinding` -> `PrioritizedFinding` |
| Remediator | `src/vulntriage/remediator.py` | `PrioritizedFinding` -> `RemediatedFinding` |
| Report Composer | `src/vulntriage/report_composer.py` | `List[RemediatedFinding]` -> HTML + PDF |
| Plain-text Reporter | `src/vulntriage/reporter.py` | `List[PrioritizedFinding]` -> text report |
| Eval harness | `src/vulntriage/evaluation.py` | dataset + ground truth -> metrics JSON/CSV |
| LLM client | `src/vulntriage/llm.py` | OpenAI-compatible (LM Studio / Ollama / OpenRouter / OpenAI / …); `--local-only` gates cloud providers |

## Risk score formula

```
Risk = (CVSS/10 × 0.5) + (Exploitability × 0.3) + (Asset × 0.2)
```

Where exploitability is High=1.0, Medium=0.5, Low=0.1.

## Ground-truth label mapping (evaluation)

The evaluation uses CVSS temporal exploit maturity (E) as a proxy for human
expert labels. Findings are excluded from the accuracy metric when no maturity
data is available (`X` / no CVE), but retained for the ranking and latency
metrics:

| CVSS-E | Meaning | Ground-truth label |
|---|---|---|
| H / F | functional exploit available | High |
| P | proof-of-concept available | Medium |
| U | no exploit available | Low |
| X | no temporal data | excluded from accuracy |

## RAG knowledge base

`data/cve_kb.json` is a curated mapping of CVE / service -> mitigation steps.
The remediator looks up the finding's CVE first, then falls back to a
service-class entry, and injects matching guidance into the remediation prompt
when `--rag` is set (the default). Use `--no-rag` to compare against ungrounded
LLM remediation.

## Tests

```bash
uv run pytest
uv run pytest --cov=vulntriage
```
