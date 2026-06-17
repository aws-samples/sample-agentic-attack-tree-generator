# ThreatForest → TypeScript migration log

Status of the Python → TypeScript migration. The legacy Python pipeline under
`../src` (minus the kept ML service) remains runnable until cutover is signed off.

## What moved, and where

| Legacy (Python) | New (TypeScript) | Status |
|---|---|---|
| `src/threatforest/agents/*` (Strands pipeline) | `ts/packages/engine` (`@strands-agents/sdk`) | ✅ ported, typechecks, deterministic stages parity-tested |
| `src/threatforest/types/*`, `modules/models/*`, `src/server/models.py` | `ts/packages/types` (Zod) | ✅ |
| `src/server/*` (FastAPI + routes + WS) | `ts/packages/server` (Express 5 + ws) | ✅ boots, frozen contract preserved |
| `src/threatforest/cli.py` | `ts/packages/cli` (commander) | ✅ (some Python-only subcommands stubbed — see below) |
| `console-ui/` (Vite React JS) | `ts/web` (Next.js 15, TS, static export) | ✅ builds + static-exports |
| `src/threatforest/embedding`, `modules/graph`, STIX data | **kept Python** → `src/ml_service` (FastAPI) | ✅ extracted as a warm service |

## Parity evidence (the acceptance gate)

LLM stages are non-deterministic, so parity is enforced on the **deterministic**
stages — the contract the UI and downstream consumers depend on:

- **probability** — `ts/packages/engine/src/stages/probability.test.ts`: TS output
  byte-for-byte equal to Python `compute_probabilities` (probability + reach to
  1e-9; rationale strings character-for-character). Fixture generated from real Python.
- **report bundle** — `report.parity.test.ts`: TS `threatforest_data.json`
  structurally identical to Python `run_report_generator` (tree count, mermaid,
  ttc_mappings). Fixture generated from real Python.
- **ML service** — `src/ml_service/tests/test_parity.py`: `/match_steps` returns
  the same top-K technique IDs/scores/frameworks as the in-process `TTCMatcher`
  (verified across ATT&CK/ATLAS/AWS frameworks incl. the AWS-term boost).
- **WS-0 spikes** — `ts/packages/spike`: proved the TS SDK reproduces the HITL
  Graph interrupt→resume contract and Zod `structuredOutputSchema` on Bedrock.

End-to-end: the compiled TS server serves the Next static export (`/` →
index.html + `_next` assets), `/api/*` works, and SPA fallback serves the shell
for client routes — verified by smoke test.

## Known follow-ups (carried, not silently dropped)

1. **Provider reduction (7 → 4).** TS SDK is first-class for Bedrock / Anthropic /
   OpenAI / Gemini. Legacy Ollama / LiteLLM / SageMaker / LlamaAPI are not
   first-class; reach Ollama/LiteLLM via the OpenAI-compatible endpoint. Confirm
   acceptable with stakeholders; README/config updated.
2. **Per-node WebSocket streaming.** The executor currently surfaces run
   lifecycle + terminal status; fine-grained per-node progress (consuming
   `graph.stream()` node events) is a follow-up. The run-progress UI works on the
   lifecycle events today.
3. **Binary-document reads (PDF/Office).** Deferred in the TS sandboxed-file tool
   (returns a placeholder string); the Python pipeline still extracts them.
4. **`mitigation.ts` tool duplication.** The mitigation agent carries its own copy
   of the sandboxed read tool; dedupe against `tools/sandboxed-file.ts`.
5. **CLI stubs.** `run --mode enrich|mitigate`, `export traces`, and live
   AWS/Langfuse connection probes / score registration print a not-available
   notice (Python-only deps); credentials still persist to `.env`.
6. **Control-catalog embedding** (`mitigation` control candidates) is a Python
   placeholder that wrote empty candidates; the TS port preserves that behaviour
   (no AWS Control Catalog endpoint exists on the ML service yet).
7. **Server `/config/test` + `versions/:id/data` STIX enrichment** are
   field-shape-faithful but skip the live Python-only checks/enrichment.

## Cutover checklist

1. Build: `npm install` in `ts/`; `npm run build -w @threatforest/types`;
   `tsc -b packages/engine packages/server packages/cli`; `cd web && next build`.
2. Run the Python ML service: `python -m ml_service`.
3. Start the TS server (serves `ts/web/out` + `/api` + `/ws`).
4. Validate against the parity tests + a real repo→report run.
5. Flip the package entry point / launcher to the TS CLI; retire the Python
   pipeline once a full run is signed off. Keep `src/ml_service` (Python stays).
