# Design: LLM-Enabled Vulnerability Triage Pipeline (v1)

## Goal

Build a minimal end-to-end pipeline that ingests scanner results (Nmap, Nuclei, synthetic), enriches each finding with LLM-generated threat context, assigns an exploitability label (High/Medium/Low), and produces a simple ranked text report — with every module independently evaluable for accuracy and latency, and every LLM call swappable between local (LM Studio) and cloud (OpenRouter) providers.

## Thesis Question

> Can an LLM-driven vulnerability triage pipeline improve both exploitability scoring accuracy against human expert labels and triage throughput over raw CVSS-based prioritization?

The thesis measures two dimensions: (A) accuracy of LLM exploitability labels vs. human expert ratings and vs. CVSS-only baselines; (B) time-to-triage reduction (latency and analyst effort) compared to manual review of raw scanner output.

## Assumptions

- **Scanner input formats**: Nmap XML output, Nuclei JSONL output, and a hand-crafted synthetic JSON schema. All are normalized into a common internal `Finding` model before downstream processing.
- **Nuclei is dockerized**: A wrapper script invokes the local Docker image (`my-nuclei:latest`, built from `docker/nuclei/Dockerfile`) with `-jsonl` output. The parser reads the resulting JSONL file.
- **LLM abstraction**: A single `LLMClient` interface with two backends — `OpenRouterClient` (OpenAI-compatible API, pointed at OpenRouter) and `LMStudioClient` (local, OpenAI-compatible at `localhost:1234/v1`). The rest of the pipeline never knows which provider is running.
- **LLM calls are structured**: Each module uses a templated prompt that returns structured JSON, parsed via Pydantic — no free-text parsing.
- **Exploitability labeling**: Three tiers (High/Medium/Low) based on LLM reasoning about exposure, public exploit availability, and attack complexity. Not a numerical score yet — that's scope for v2.
- **Assets**: A simple static asset registry (YAML) with hostname→criticality mappings (1.0 = critical, 0.5 = normal, 0.1 = low). No auto-discovery.
- **MVP scope**: v1 produces a plain-text ranked report. No PDF, no HTML, no executive summary — that's the Final Report Composer for later.
- **No remediation module in v1**: The pipeline stops at prioritized findings. Remediation is v2.
- **Ethics**: Only scans the operator's own network. No external targets.

## Unknowns / Risks

- **LLM accuracy on exploitability**: Small local models (≤4B params) may produce inconsistent or wrong labels. The evaluation framework must measure this explicitly so the thesis can quantify the gap between local and cloud models.
- **Prompt sensitivity**: Structured JSON output from small models can be flaky. May need fallback parsing or retry logic.
- **Nmap/Nuclei on home LAN**: Depends on what's actually reachable. Scan results may be sparse (a few open ports, one outdated service). Synthetic data will carry most of the evaluation weight.
- **OpenRouter costs**: Need to track token usage. Some models on OpenRouter are free, but GPT-4o is not. Budget should be a consideration.

## Proposed Approach

**Modular pipeline with typed interfaces.** Every module has exactly one job, receives a typed Pydantic model, returns a typed Pydantic model. The LLM is injected, not imported — each module receives its `LLMClient` at construction time. This gives us:

1. **Independent evaluation**: You can measure each module's accuracy and latency separately.
2. **Provider swapping**: Change one config line to switch between LM Studio and OpenRouter.
3. **Testability**: Mock the LLM, test the pipeline logic.
4. **Thesis-ready traceability**: Each module's output is logged/saved, so your evaluation chapter has a complete audit trail.

### Modules in v1

| # | Module | Input | Output |
|---|--------|-------|--------|
| 1 | **Parser** | Scanner files (Nmap XML / Nuclei JSONL / synthetic JSON) | `List[RawFinding]` |
| 2 | **Context Enricher** | `List[RawFinding]` | `List[EnrichedFinding]` |
| 3 | **Exploitability Scorer** | `List[EnrichedFinding]` | `List[ScoredFinding]` |
| 4 | **Prioritizer** | `List[ScoredFinding]` | `List[PrioritizedFinding]` |
| 5 | **Reporter** | `List[PrioritizedFinding]` | `str` (plain-text ranked report) |

No remediation, no PDF/HTML, no executive summary. Those are v2.

## Step-by-Step Plan

1. **Set up project structure** — create `src/vulntriage/` with `__init__.py`, `models.py`, `llm.py`, and one file per module.
2. **Define data models** (`models.py`) — `RawFinding`, `EnrichedFinding`, `ScoredFinding`, `PrioritizedFinding` as Pydantic models. Normalize Nmap XML, Nuclei JSONL, and synthetic JSON into `RawFinding`.
3. **Build LLM abstraction** (`llm.py`) — `LLMClient` protocol with `complete(prompt: str) -> str`. Implement `OpenRouterClient` and `LMStudioClient`. Both point at OpenAI-compatible endpoints.
4. **Build the Parser** — read Nmap XML with `xml.etree`, read Nuclei JSONL, read synthetic JSON, normalize all to `List[RawFinding]`. Include a small sample synthetic file for testing.
5. **Build the Nuclei scanner runner** — a small wrapper that invokes `docker run --rm my-nuclei:latest -jsonl -u <targets>` and writes output to a file the parser can read.
6. **Build the Context Enricher** — templated prompt asking the LLM to produce threat context, real-world attack scenarios, and business impact. Parse structured JSON output into `EnrichedFinding`.
7. **Build the Exploitability Scorer** — templated prompt with few-shot examples for High/Medium/Low. Parse JSON label into `ScoredFinding`.
8. **Build the Prioritizer** — static formula: `Risk Score = (CVSS × 0.5) + (Exploitability × 0.3) + (Asset Criticality × 0.2)`. Sort descending. No LLM call here — it's pure logic.
9. **Build the Reporter** — plain-text output with header, per-finding section (title, context, score, risk rank), and a final sorted table.
10. **Wire up `main.py`** — CLI with `--input`, `--provider` (openrouter|lmstudio), `--model`, `--asset-registry` flags. Run the full pipeline.
11. **Write the evaluation harness skeleton** — a script that measures per-module latency and saves intermediate outputs, ready for your accuracy evaluations later.

## Files / Areas Likely Affected

```
src/
  vulntriage/
    __init__.py
    models.py          # Pydantic models
    llm.py             # LLMClient, OpenRouterClient, LMStudioClient
    parser.py          # Nmap XML + Nuclei JSONL + synthetic JSON → RawFinding
    scanner.py          # Dockerized Nuclei runner
    enricher.py        # RawFinding → EnrichedFinding (LLM)
    scorer.py          # EnrichedFinding → ScoredFinding (LLM)
    prioritizer.py     # ScoredFinding → PrioritizedFinding (formula)
    reporter.py        # PrioritizedFinding → plain-text report
    cli.py             # Argument parsing + pipeline orchestration
data/
  assets.yaml          # Asset criticality registry
  synthetic_findings.json  # Hand-crafted test data
  sample_nmap.xml      # Example Nmap output
  sample_nuclei.jsonl  # Example Nuclei JSONL output
main.py                # Entry point
pyproject.toml         # Dependencies (pydantic, httpx, openai)
```

## Validation

- **Smoke test**: Run `uv run python main.py --input data/synthetic_findings.json --provider lmstudio --model qwen3.5-4b` and confirm a ranked report prints.
- **Provider swap**: Run the same command with `--provider openrouter --model openai/gpt-4o` and confirm it works identically.
- **Nuclei path**: Run `uv run python main.py --input data/sample_nuclei.jsonl --provider lmstudio --model qwen3.5-4b` and confirm Nuclei findings parse and enrich correctly.
- **Latency logging**: Confirm each LLM call logs its duration (for thesis time-efficiency metric).
- **Output inspection**: Manually review 2–3 enriched findings for hallucination or nonsense.
- **Reproducibility**: `uv run python main.py --help` works from a fresh clone after `uv sync`.
