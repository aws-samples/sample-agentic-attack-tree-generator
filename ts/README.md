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
                                                         ▼  HTTP (localhost)
                                          Python ML service  (ATTACK-BERT + STIX)
```

- **ML stays Python.** The embedding/MITRE-match layer (sentence-transformers,
  ATTACK-BERT, STIX vector search) has no TS equivalent and runs as a warm
  service; the TS TTP stage calls its `/match_steps` endpoint.
- **Providers.** The Strands TS SDK is first-class for **Bedrock, Anthropic,
  OpenAI, and Gemini**. The legacy Python config also supported Ollama, LiteLLM,
  SageMaker, and LlamaAPI — those are **not** first-class in the TS build. Reach
  Ollama/LiteLLM by pointing the `openai` config block at their
  OpenAI-compatible endpoint.

## Running locally

1. **Start the Python ML service** (loads ATTACK-BERT + STIX once):
   ```bash
   cd ..            # repo root
   python -m ml_service          # serves http://127.0.0.1:8770
   ```
2. **Build the TS packages:**
   ```bash
   cd ts
   npm install
   npm run build -w @threatforest/types
   npx tsc -b packages/engine packages/server
   ```
3. **Start the server** (serves /api + /ws on :8000):
   ```bash
   npm run start -w @threatforest/server
   ```
4. **Dev the UI** (proxies /api + /ws to :8000):
   ```bash
   cd web && npm run dev          # http://localhost:3000
   ```
   Or build the static export and let the server host it:
   ```bash
   cd web && npm run build        # -> web/out, served by the TS server
   ```

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
