# Design: Multi-LLM Ensemble Scoring + Model Picker + local-only reorder

## Goal

Three related changes to the triage intake flow (CLI + webapp), converging on
the same "provider / model" form area:

1. **Move the local-only checkbox above the provider selection** in both the
   triage and the eval intake forms, so it visually gates the provider list
   *before* the operator picks a provider.
2. **Populate the model field by querying each provider's OpenAI-compatible
   `/models` endpoint**, while always preserving the ability to type a custom
   model name by hand.
3. **Add a multi-LLM ensemble mode that runs the exploitability scorer against
   N models and merges the per-finding High/Medium/Low votes by strict
   majority (m-of-n quorum), to reduce false positives.**

The single-model path stays byte-identical to today (same `run_pipeline`
signature, same report output, existing tests green); ensemble is an opt-in.

## Scope decision — and why (scoring-only ensemble)

The pipeline is: `enrich (LLM, free text) → score (LLM, High/Med/Low label) →
prioritize (deterministic) → remediate (LLM, free text) → report`. The
ensemble fans out at **scoring only**:

- **Why scoring, not enrichment/remediation:** the exploitability label is the
  single triage decision where false positives concretely bite (it sets the
  rank and the severity badge the operator acts on first). It is a *categorical*
  output (High/Med/Low), so merging is a clean, auditable vote — no free-text
  reconciliation. Fanning out enrichment or remediation would multiply LLM
  calls to merge *prose*, which is messy, hard to defend in a thesis, and
  adds cost without directly addressing the false-positive goal. The whole
  point of an ensemble for triage is "don't flag it High unless enough models
  agree"; that decision lives in the scorer.
- **Why not whole-pipeline replication:** running N independent
  enrich→score→remediate pipelines and merging two full ranked lists is the
  most expensive option and the merge is the hardest (you reconcile two
  complete orderings). The benefit over scoring-only is marginal because the
  *enrichment* text and *remediation* steps don't disagree in a way a vote
  resolves — they just differ in prose quality. We keep them single-model.

So: **N models score each finding; enrichment, prioritization, remediation,
and report composition run once on the merged labels.** Comparison is still
visible in the final report — each finding shows the per-model vote
breakdown — satisfying the "compare results" intent without paying for
whole-pipeline replication.

## Merge rule decision — and why (strict-majority m-of-n)

Each of the N models emits a label per finding. We merge with a **strict
majority quorum**: a label is accepted as the final `exploitability` only if
**≥ k** of the N models agree on it, where the default is
**k = ⌊N/2⌋ + 1** (i.e. 2-of-3, 3-of-5). If no label reaches quorum, the
finding is marked **`Unresolved`** and gets its own section in the report.

- **Why strict majority, not plain majority-with-tiebreak:** a plain majority
  resolves ties by a fixed default (e.g. Medium), which *reintroduces* a
  single-model-style guess and defeats the purpose of the ensemble. The whole
  premise of "reduce false positives" is that a lone High from one model
  should **not** silently become a final High; strict majority enforces that.
  If two of three models say High, that's a real signal and becomes High; if
  they split High/Med/Low, the operator is told "the models disagree, look at
  this one" instead of being handed a confident lie.
- **Why Unresolved-on-no-quorum, not a fallback label:** surfacing
  disagreement to the human is exactly the honest behaviour a triage tool
  should have under uncertainty. Fabricating a label would re-create the
  false-positive problem the ensemble exists to prevent.
- **Why k = ⌊N/2⌋ + 1 default:** this is the smallest threshold that is both
  (a) a genuine majority (more than half) and (b) achievable for odd N, so it
  generalizes cleanly from 2-of-3 to 3-of-5 without per-N tuning. It is
  configurable via `--quorum` / a form field, but the default is principled
  and needs no operator fiddling.

The vote breakdown (model -> label) and the accepted quorum are stored on
each scored finding and rendered in the report so the merge is transparent
and reproducible — a thesis requirement.

## Assumptions

1. **Every provider exposes the OpenAI-compatible `/v1/models` endpoint.**
   This is already true for the local set (lmstudio, ollama, llamacpp, vllm)
   and for openai/openrouter/deepseek/anthropic/google in their
   OpenAI-compatible mode; we already assume OpenAI-compat for chat
   completions, so `/models` is the same assumption extended to listing.
2. **`/models` is best-effort.** If the endpoint is unreachable or errors,
   the model field falls back to plain free-text input with no dropdown — the
   run is still submittable. We never block a run on `/models` failing.
3. **API keys come from the environment** (today's `make_client` wiring); we
   do **not** add a key-entry field to the form. `/models` is queried
   server-side using the same env-backed client construction.
4. **Ensemble is opt-in and only affects scoring.** Enrichment, remediation,
   and report composition use a single "primary" client (the first
   provider/model pair, which is **also** the first member of the ensemble).
   The single-model path is unchanged in behaviour and output. The strict-
   majority quorum `k = ⌊N/2⌋ + 1` means for **even N** a quorum requires
   *unanimous* agreement (e.g. N=2 → k=2, so both models must agree or the
   finding is Unresolved); for **odd N** a bare majority suffices (N=3 → k=2,
   so 2 of 3 resolves even with one dissenter). This is the intended property:
   small ensembles err toward surfacing disagreement rather than guessing.
5. **N is small (2–5).** No effort to scale to many models; cost grows as
   O(N × findings) for scorer calls only.
6. **`Unresolved` is a display/merge state, not a new `Exploitability` enum
   member on `ScoredFinding`.** The stored `exploitability` field keeps its
   High/Med/Low enum so prioritizer/scoring metrics are unaffected; the
   unresolved case is represented by a flag (`ensemble_unresolved: bool`)
   and the report renders it distinctly. This avoids touching
   `Exploitability.numeric()` (used by the prioritizer formula) and the CVSS-E
   accuracy metrics, which are scoped to High/Medium/Low.
7. **Run record gains an optional `ensemble` sub-dict** (providers, models,
   quorum) stored in `RunRecord.params`; existing single-model `params` JSON is
   unchanged (the new keys are simply absent).
8. **Tests assert on specific fields, not exact dict equality** (verified in
   `tests/test_pipeline.py`, `tests/conftest.py`), so additive optional fields
   on `ScoredFinding` are safe.

## Unknowns / Risks

| Risk | Severity | Mitigation |
|---|---|---|
| `/models` shapes differ across providers (some return `data[].id`, some `data[].body.model`, etc.) | Medium | Parse defensively: try `data[].id`, then `data[].body.model`, then `data[].model`; dedupe & sort; on any failure, return `[]` so the UI falls back to free text |
| A cloud provider's `/models` lists hundreds of models, swamping the dropdown | Low | Cap the rendered list (e.g. 200 entries), dedupe, sort alphabetically; the datalist is a *suggestion* overlay, free text is always available |
| Ensemble makes N× scorer calls → slower runs | Medium | Scorer calls already run sequentially; N is small; progress log prints per-model lines so the operator sees activity; documented in the form hint |
| Models disagree on every finding → many `Unresolved` | Low | That is the *correct* signal; report surfaces it; the operator can lower `--quorum` or inspect per-finding votes |
| Backward-compat for `score_all` callers (existing tests pass a single client) | Low | Keep `score(... , client)` and `score_all(... , client)` signatures; add an optional `clients: list[LLMClient] | None = None` and `quorum: int | None = None`. When `clients` is None, behaviour is exactly today's |
| CLI `--ensemble` parsing ambiguity (`provider:model` where model name contains a colon) | Low | Split on the **first** colon only (`str.split(":", 1)`); document it |
| Eval mode already varies models across cells → ensemble inside eval is double-counting | Low | Ensemble is a **triage-run** feature only; `--evaluate` (the experiment grid) is out of scope for ensemble and unchanged |

## Proposed Approach

### Models endpoint (todo 2)

Add `vulntriage/llm.py::list_models(provider) -> list[str]`:

- Build the same base_url/api_key `make_client` would use (refactor the
  per-provider base_url/api_key resolution into a small `_provider_config(provider)
  -> tuple[base_url, api_key, local]` helper reused by both `make_client` and
  `list_models`, so we don't duplicate the env wiring).
- Open a plain `httpx`/`openai` call to `GET {base_url}/models` (the OpenAI
  SDK exposes `client.models.list()`). Parse `data[].id` defensively.
- Return a sorted, deduped list of model id strings. On any exception, return
  `[]` (best-effort; never raises).

Add a webapp route:

```
GET /models?provider=<name>   -> JSONResponse({"models": [...], "error": null | str})
```

It calls `list_models(provider)` and respects `local_only` only in that the
provider must be known (it does not need the local_only flag — the provider
<select> is already gated). No key is exposed to the client.

### Form UX (todo 2)

The model field becomes an `<input>` with a `<datalist>` of suggestions
fetched from `/models` when the provider `<select>` changes:

```html
<input list="models-dl" name="model" required placeholder="qwen3.5-4b">
<datalist id="models-dl"></datalist>
```

`<datalist>` is pure suggestion — the user can always type a custom value, so
"ability to write my own" is guaranteed by the HTML primitive, no JS special
case. On provider change, `app.js` does `fetch('/models?provider=' + …)` and
repopulates the `<datalist>`. On fetch failure, the datalist is emptied (free
text remains). No spinner needed; suggestions just appear.

### Local-only reorder (todo 1)

In `run_new.html` and `eval_new.html`: move the "Block cloud providers /
Local only" `.row` to **above** the provider `.row`. The existing `onchange`
handler (which hides non-local `<option>`s when checked) already works
wherever the checkbox sits — no logic change, just DOM order. The handler is
also adjusted to reset the model datalist when local-only toggles (since the
provider may auto-switch to the first local option, the model suggestions must
refresh).

### Ensemble wiring (todo 3)

**Data model** (`models.py`): two new optional fields on `ScoredFinding`,
defaulting so single-model runs are unaffected:

```python
exploitability_votes: dict[str, str] = Field(default_factory=dict,
    description="model_name -> label, populated only in ensemble mode")
ensemble_quorum: int | None = Field(default=None,
    description="accepted-quorum threshold, populated only in ensemble mode")
ensemble_unresolved: bool = Field(default=False,
    description="True when no label reached quorum (display-only)")
```

Because they default empty/None/False, a single-model `ScoredFinding.model_dump()`
just adds `exploitability_votes: {}`, `ensemble_quorum: null`,
`ensemble_unresolved: false` — existing tests assert on specific fields
(`exploitability`, counts), not exact dict equality, so they stay green.
Unresolved findings are **excluded** from the CVSS-E accuracy metric
(that metric maps E-scores to High/Medium/Low only, so `Unresolved` has no
ground-truth match); they still get a risk score and a rank (see merge
fallback below) and a distinct report badge.

**Scorer** (`scorer.py`): extend `score_all` with two optional params:

```python
def score_all(findings, client, *, few_shot=True,
              clients: list[LLMClient] | None = None,
              quorum: int | None = None) -> list[ScoredFinding]: ...
```

- If `clients is None`: exactly today's behaviour (one `client`, no votes
  recorded). This is the path the CLI and webapp use today and the path tests
  exercise.
- If `clients` is a non-empty list: for each finding, call `score(...)` once
  per client, collect `{client.model: label}`. Then:
  - If `quorum is None`: `quorum = len(clients)//2 + 1`.
  - Tally votes per label; if a label's count ≥ quorum, that's the final
    `exploitability` and `ensemble_unresolved = False`.
  - Else `ensemble_unresolved = True` and the `exploitability` is set to the
    **highest** tally label (so the deterministic prioritizer still ranks it
    somewhere sane), but the report renders it as `Unresolved` and flags it.
    Unresolved findings are excluded from the High/Med/Low accuracy metric
    (no ground-truth match), but still appear in ranking and latency metrics.
  - `exploitability_rationale` is composed from the votes as a tally+quorum
    summary, e.g. `"2/3 models: High=2, Medium=1 (quorum 2 -> High)"` — fully
    transparent (ASCII `->`, since this string also appears in plain-text
    reports).
  - The returned `ScoredFinding` carries `exploitability_votes`,
    `ensemble_quorum`, `ensemble_unresolved`, `scoring_model` set to the
    primary model's name.
  - `score()` (single) is unchanged.

**Pipeline** (`pipeline.py`): `run_pipeline` gains:

```python
def run_pipeline(findings, client, *, ...,
                 scoring_clients: list[LLMClient] | None = None,
                 scoring_quorum: int | None = None) -> RunResult:
```

The scoring step becomes:

```python
if scoring_clients:
    scored = score_all(enriched, client, few_shot=few_shot,
                       clients=scoring_clients, quorum=scoring_quorum)
else:
    scored = score_all(enriched, client, few_shot=few_shot)
```

Enrichment and remediation still use the single primary `client`. No other
step changes.

**Report** (`report_composer.py` + `data/templates/report.html`,
`reporter.py`):

- The HTML/PDF report renders, for each finding, the per-model vote
  breakdown when `exploitability_votes` is non-empty, and an **`Unresolved`**
  badge (distinct from High/Med/Low colors) when `ensemble_unresolved`.
- The plain-text reporter (`reporter.py`) prints `[UNRESOLVED]` in the rank
  table for unresolved findings. It also appends a per-model breakdown line
  `Votes: model=label, ...` (e.g. `Votes: a=High, b=High, c=Medium`) when
  `exploitability_votes` is non-empty; the tally+quorum summary itself lives
  in the pre-existing `Exploitability rationale:` line, which already prints
  `exploitability_rationale`, so the rationale and the raw votes are both
  visible without duplication.
- The executive summary gains one sentence when ensemble mode was used,
  naming the model count, the strict-majority quorum, and the count of
  Unresolved findings (worded as "Exploitability was scored by an N-model
  ensemble (strict-majority quorum k); X finding(s) were Unresolved …").

**Run record** (`runs.py`): `start_triage[_scan]` accept an optional
`ensemble: list[tuple[str, str]] | None` (list of (provider, model)) and
`quorum: int | None`. The worker builds N clients for scoring and one primary
client for enrich/remediate. `RunRecord.params` stores
`ensemble: [{provider, model}, ...], quorum` when set; absent for single-model
runs (so existing `params` JSON shape is preserved).

**Dossier** (`run_detail.html`): the manifest adds an "Ensemble (scoring)"
field showing `N model(s) + primary · quorum …` plus the member list when
`params.ensemble` is set; the listing dashboard keeps its compact
`provider · model` one-line meta and is intentionally unchanged (an ensemble
marker there would just be noise).

### Form UX (todo 3) — opt-in, repeated rows

In `run_new.html`:

- The single (provider, model) row stays as the default.
- A checkbox **"Multi-LLM ensemble (scoring only)"** reveals an "Additional
  scoring models" section with an **Add model** button that appends a new
  (provider `<select>` + model `<input list=…>`) row, reusing the same
  `/models` datalist logic per row.
- A **"Quorum"** field appears (default: `⌊N/2⌋+1`, computed/auto-filled but
  editable) with a hint explaining strict majority.
- The primary (first) row's provider+model is used for enrichment +
  remediation; the additional rows (plus the primary) are the ensemble.
- When the checkbox is unchecked, the extra rows are removed from the
  submitted form (JS clears those inputs), so the POST is identical to
  today's single-model submission.

The `POST /runs/new` handler accepts repeated form fields:
`provider`/`model` (primary) plus `ensemble_provider[]`/`ensemble_model[]`
(repeated). When the ensemble list is non-empty and ≥1 extra model is
present, the run is ensemble-mode.

### CLI (todo 3)

Add to `cli.py`:

```
--ensemble <provider:model>[,<provider:model>...]   # additional scoring models
--quorum <int>                                       # default: floor(N/2)+1
```

The primary `--provider`/`--model` is still required (used for enrich +
remediate, and is the first ensemble member). `--ensemble` adds the rest.
`--local-only` validates **every** ensemble member (extended
`_check_local_only` to walk the ensemble list).

Example:

```
uv run python main.py --input data/synthetic_findings.json \
  --provider lmstudio --model qwen3.5-4b \
  --ensemble ollama:llama3.1,openai:gpt-4o-mini --quorum 2 --remediate
```

## Step-by-Step Plan

1. **Refactor provider config** — extract `_provider_config(provider) -> (base_url, api_key, local)` in `llm.py`; `make_client` uses it. No behaviour change. `ruff check`.
2. **`list_models(provider)`** — in `llm.py`, using `openai.OpenAI(base_url, api_key).models.list()` defensively; return `[]` on error. Unit-ish test with a mock.
3. **Webapp `/models` route** — `GET /models?provider=...` in `app.py`. Test in `test_webapp.py` (mock `list_models`).
4. **local-only reorder** — move the `.row` above provider in `run_new.html` and `eval_new.html`; adjust the toggle handler to refresh the model datalist on provider auto-switch.
5. **Model datalist** — add `<datalist>` + the `app.js` fetch-on-provider-change logic; reuse for every model row (including future ensemble rows).
6. **`ScoredFinding` fields** — add `exploitability_votes`, `ensemble_quorum`, `ensemble_unresolved` to `models.py` (defaults preserve single-model).
7. **`score_all` ensemble** — add `clients`/`quorum` params to `scorer.py`; implement the strict-majority merge + Unresolved handling + rationale composition. `score()` unchanged.
8. **`run_pipeline` ensemble** — add `scoring_clients`/`scoring_quorum` params; wire the scoring branch. No other step changes.
9. **Report rendering** — `report_composer.py` context + `data/templates/report.html` (vote breakdown + Unresolved badge); `reporter.py` plain-text vote line + `[UNRESOLVED]`.
10. **`runs.py`** — `start_triage`/`start_triage_scan` accept `ensemble` + `quorum`; worker builds N scoring clients + 1 primary; `params.ensemble` stored only when set.
11. **`app.py` POST `/runs/new`** — accept `ensemble_provider[]`/`ensemble_model[]` + `quorum`; validate local-only across all; build the clients list; pass to `start_triage`.
12. **`cli.py`** — `--ensemble`, `--quorum`; extend `_check_local_only` to the ensemble; build `scoring_clients` and pass to `run_pipeline`.
13. **`run_new.html` ensemble UI** — the toggle, the repeated-row "Add model" section, the quorum field, the JS that clears extra inputs when unchecked.
14. **`dashboard.html` / `run_detail.html`** — manifest "Ensemble: N (quorum k)" line.
15. **Tests** — new `test_scorer_ensemble.py` (ensemble merge + Unresolved;
the Unresolved branch is exercised with mock clients returning *different*
labels, since identical mocks always agree), `test_cli_ensemble.py`
(`--ensemble` + `--quorum` parsing and passing, local-only blocking of cloud
ensemble members), `test_webapp_models_ensemble.py` (`/models` route
best-effort/unknown/exception, ensemble `POST /runs/new` recorded in params,
mismatched-length rejection, and the local-only-above-provider form
assertion). The single-model paths are covered by the pre-existing tests,
which stayed unchanged.
16. **Lint/format** — `ruff check --fix`, `ruff format`.
17. **Docs** — this design doc; README CLI examples;

## Files / Areas Likely Affected

```
src/vulntriage/
  llm.py               # _provider_config, list_models
  models.py            # ScoredFinding: +votes +quorum +unresolved
  scorer.py            # score_all: +clients +quorum (strict majority)
  pipeline.py          # run_pipeline: +scoring_clients +scoring_quorum
  reporter.py          # plain-text vote line + [UNRESOLVED]
  report_composer.py   # context: votes + Unresolved badge
  cli.py               # --ensemble, --quorum, _check_local_only extension
  webapp/app.py        # GET /models, POST /runs/new ensemble fields, _validate_provider
  webapp/runs.py       # start_triage[_scan]: +ensemble +quorum; worker builds N clients
  webapp/static/app.js # /models fetch + datalist repopulate + Add-model rows
  webapp/templates/run_new.html     # local-only reorder, datalist, ensemble UI
  webapp/templates/eval_new.html     # local-only reorder, datalist
  webapp/templates/run_detail.html   # ensemble manifest line
data/templates/report.html           # vote breakdown + Unresolved badge
tests/
  test_scorer_ensemble.py        # NEW: ensemble merge + Unresolved (different-label mocks)
  test_cli_ensemble.py           # NEW: --ensemble / --quorum parsing + local-only gating
  test_webapp_models_ensemble.py # NEW: /models route + ensemble POST + local-only-above-provider form assertion
README.md                # CLI ensemble example, /models note
docs/specs/ensemble-and-model-picker-design.md   # THIS
```

## Validation

- `uv run pytest` green; existing single-model tests unchanged.
- `ruff check` / `ruff format` clean.
- **Form order:** in `/runs/new` and `/eval/new`, the "Local only" checkbox
  renders above the provider `<select>`.
- **Model picker:** changing the provider dropdown fetches `/models` and
  populates the model `<datalist>`; a custom model name can still be typed and
  submitted; if `/models` errors, the field still accepts free text and the
  run submits.
- **`GET /models?provider=lmstudio`** returns JSON `{"models": [...],
  "error": null}` (mocked in tests).
- **Ensemble (CLI):** `--provider lmstudio --model qwen3.5-4b --ensemble
  ollama:llama3.1,openai:gpt-4o-mini --quorum 2` produces a report where each
  finding's vote breakdown is shown and at least one finding can be
  `Unresolved` when models disagree.
- **Ensemble (webapp):** toggling "Multi-LLM ensemble", adding ≥1 model, and
  submitting drives a run whose dossier manifest says "Ensemble: N (quorum
  k)" and whose report shows votes.
- **Local-only + ensemble:** ticking "Local only" with a cloud model in any
  ensemble row is rejected with the same 400 as today (extended message lists
  the offending row).
- **Backward-compat:** a single-model run's `intermediates/scored.json`
  adds the three fields with their defaults
  (`exploitability_votes: {}`, `ensemble_quorum: null`,
  `ensemble_unresolved: false`) and no existing test breaks.