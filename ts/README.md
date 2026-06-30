# ThreatForest — TypeScript stack

This directory holds the TypeScript rewrite of ThreatForest: the Strands agent
pipeline, the API server, the CLI, and the Next.js dashboard. The Python ML /
MITRE layer is kept and runs as a small standalone service the TS pipeline calls.

> Status: migration in progress (see `MIGRATION.md` for the workstream log and
> the parity gates). The legacy Python pipeline under `../src` remains runnable
> until cutover is signed off.

## Layout

```
ts/
  packages/
    types/     @threatforest/types   — shared Zod schemas + inferred types
                                        (domain, ML-service contract, API, UI graph)
    engine/    @threatforest/engine  — the Strands TS agent pipeline:
                                        scanner→threat→tree→ttp→mitigation→
                                        probability→report, HITL nodes, the graph
                                        orchestrator, providers, ML client, tracing
    server/    @threatforest/server  — Express 5 + ws; the frozen /api + /ws contract
    cli/       @threatforest/cli      — the `threatforest` command (web console, run
                                        wizard, config)
  web/         @threatforest/web      — Next.js 15 app-router dashboard (static export)
  test-fixtures/                      — deterministic sample app for parity tests
```

The Python ML service lives at `../src/ml_service` (`python -m ml_service`).

## Architecture

```
Next.js UI ──HTTP /api  +  WS /ws──▶ TS server ──▶ engine graph (Strands TS SDK)
 (static export)                                         │
                                                         ▼  in-process
                                       TTP matching: transformers.js + ATTACK-BERT
                                       ONNX + STIX vector search  (pure TS)
```

- **ML runs in-process (pure TS), by default.** The TTP stage embeds attack
  steps with `transformers.js` running a converted ATTACK-BERT ONNX model
  (mpnet, 768-dim, mean pooling) and does STIX cosine search in TS — no Python
  process. Numerically faithful to the Python pipeline: top-1 MITRE techniques
  match exactly (T1530 / T1548 / T1566 verified), JS cosine 0.4860 == Python
  0.48597. One-time setup: `npm run convert-model` (PyTorch→ONNX; output
  gitignored under `ts/models/`), or host the ONNX on HuggingFace and set
  `TF_ATTACK_BERT_HF`.
- **Python ML service kept as a fallback.** `src/ml_service` still works; set
  `TF_USE_PYTHON_ML=1` (or `TF_ML_URL` with no local model) to route TTP
  matching through it instead of the in-process embedder. Backend selection
  lives in `packages/engine/src/ml/index.ts`.
- **Providers.** The Strands TS SDK is first-class for **Bedrock, Anthropic,
  OpenAI, and Gemini**. The legacy Python config also supported Ollama, LiteLLM,
  SageMaker, and LlamaAPI — those are **not** first-class in the TS build. Reach
  Ollama/LiteLLM by pointing the `openai` config block at their
  OpenAI-compatible endpoint.

## Running locally

```bash
cd ts
npm install
npm run dev                  # Python ML service (:8770) + TS server (:8000) + Next UI (:3000)
```

`npm run dev` runs the whole stack in one command. Embeddings use the **Python
ML service** by default (it's started for you via the repo `.venv`; override the
interpreter with `TF_PYTHON=…`). Open http://localhost:3000.

Variants:
- `npm run dev:no-ml` — server + UI only (point `TF_ML_URL` at an ML service you
  run separately, or opt into the in-process TS embedder, below).
- **In-process TS embeddings (opt-in):** `npm run convert-model` once (ATTACK-BERT
  → ONNX into `ts/models/`, needs the repo `.venv`), then run with
  `TF_USE_PYTHON_ML=0` — no Python ML service needed. Proven at top-1 parity with
  the Python matcher.

Other commands:
- `npm run build` — build all packages + the Next static export (`web/out`).
- `npm run start` — build, then serve the exported UI + API from the TS server on :8000.
- `npm test` — engine parity tests (probability, report, ML matcher gated on the model).

AWS auth note: if `AWS_BEARER_TOKEN_BEDROCK` is set but empty in your env, unset
it — otherwise the AWS SDK picks bearer auth over SigV4 and Bedrock calls fail
to sign.

## Tests / parity

```bash
cd ts
node --import tsx/esm --test "packages/engine/src/**/*.test.ts"
```

Parity gates (TS output proven identical to Python on the deterministic stages):
- **probability** — byte-for-byte (probability/reach to 1e-9, rationale strings
  character-for-character) vs the Python `compute_probabilities`.
- **report** — `threatforest_data.json` bundle structurally identical (trees,
  mermaid, ttc_mappings) vs the Python `run_report_generator`.
- **ML service** — `/match_steps` returns identical top-K to the in-process
  Python `TTCMatcher` (see `../src/ml_service/tests`).

LLM stages are non-deterministic, so parity is enforced on the deterministic
stages — the contract the UI and downstream consumers depend on.
