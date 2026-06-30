# LLM-Enabled Vulnerability Investigation and Triaging System

An AI-driven vulnerability triage pipeline. It ingests scanner results, enriches each finding with LLM-generated threat context, scores exploitability (High/Medium/Low), prioritizes by composite risk, and produces a ranked report.

## Thesis Question

> Can an LLM-driven vulnerability triage pipeline improve both exploitability scoring accuracy against human expert labels and triage throughput over raw CVSS-based prioritization?

## Quick start

```bash
uv sync

# Using synthetic test data with a local LM Studio model
uv run python main.py --input data/synthetic_findings.json \
    --provider lmstudio --model qwen3.5-4b \
    --asset-registry data/assets.yaml

# Using Nuclei JSONL output
uv run python main.py --input data/sample_nuclei.jsonl \
    --provider lmstudio --model qwen3.5-4b

# Using OpenRouter
OPENROUTER_API_KEY=sk-... uv run python main.py --input data/synthetic_findings.json \
    --provider openrouter --model deepseek/deepseek-v4-flash

# Using OpenAI API Platform with thinking on
OPENAI_API_KEY=sk-... uv run python main.py --input data/synthetic_findings.json \
    --provider openai --model gpt-5.4-nano --reasoning-effort high

# Run the dockerized Nuclei scanner first, then triage
docker network create -d bridge vuln-net
docker build -t my-nuclei:latest docker/nuclei
uv run python main.py --scan nuclei --target 192.168.1.5 \
    --provider lmstudio --model qwen3.5-4b

# Only run the Nuclei scan, save output and exit
uv run python main.py --scan nuclei --target 192.168.1.5 --scan-only
```

## Pipeline

```
Scanner output (Nmap XML / Nuclei JSONL / synthetic JSON)
  -> Parser         -> List[RawFinding]
  -> Context Enricher  (LLM) -> List[EnrichedFinding]
  -> Exploitability Scorer (LLM) -> List[ScoredFinding]
  -> Prioritizer   (formula) -> List[PrioritizedFinding]
  -> Reporter      -> plain-text ranked report
```

## Modules

| Module | File | Input -> Output |
|---|---|---|
| Parser | `src/vulntriage/parser.py` | scanner file -> `List[RawFinding]` |
| Nuclei runner | `src/vulntriage/scanner.py` | docker image -> JSONL file |
| Context Enricher | `src/vulntriage/enricher.py` | `RawFinding` -> `EnrichedFinding` |
| Exploitability Scorer | `src/vulntriage/scorer.py` | `EnrichedFinding` -> `ScoredFinding` |
| Prioritizer | `src/vulntriage/prioritizer.py` | `ScoredFinding` -> `PrioritizedFinding` |
| Reporter | `src/vulntriage/reporter.py` | `List[PrioritizedFinding]` -> text report |
| LLM client | `src/vulntriage/llm.py` | OpenAI-compatible (LM Studio / OpenRouter) |

## Risk score formula

```
Risk = (CVSS/10 × 0.5) + (Exploitability × 0.3) + (Asset × 0.2)
```

Where exploitability is High=1.0, Medium=0.5, Low=0.1.

See `docs/specs/2026-06-26-triage-pipeline-design.md` for the full design.
