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
                                                         ▼  HTTP :8770
                                       TTP matching: Python ML service
                                       (embeddings + STIX vector search)
```

- **The pipeline is TypeScript.** Agents, orchestration, server, CLI and UI are
  all TS; there is no second implementation and no switch between them.
- **Embeddings / TTP matching run in the Python ML service** (`src/ml_service`,
  `python -m ml_service`, binds `127.0.0.1:8770`). This is the *only* backend.
  It is Python because it is the implementation that honours `embeddings.model`,
  so alternative embedders — e.g. ThreatBERT, which outperforms ATTACK-BERT on
  TTP mapping — can be configured and used. Override the endpoint with
  `TF_ML_URL` or `TF_ML_PORT`.
- **The service is mandatory.** `runGraph` pre-flights it and refuses to start
  when it is unreachable, rather than emitting a "complete" threat model with
  silently missing attack paths (every per-threat match would otherwise throw and
  be swallowed into an empty result). A transformers.js in-process embedder was
  tried and removed: it ignored `embeddings.model` and could only load an
  ATTACK-BERT ONNX conversion, so configuring any other model silently produced
  wrong TTP mappings.
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

`npm run dev` runs the whole stack in one command, including the **Python ML
service** (started for you via the repo `.venv`; override the interpreter with
`TF_PYTHON=…`). Open http://localhost:3000.

The ML service is required — if you run the server on its own
(`npm run dev:server`), point `TF_ML_URL` at a service you started separately, or
runs will refuse to start.

Other commands:
- `npm run build` — build all packages + the Next static export (`web/out`).
- `npm run start` — build, then serve the exported UI + API from the TS server on :8000.
- `npm test` — engine parity tests (probability, report, ML matcher gated on the model).

AWS auth note: if `AWS_BEARER_TOKEN_BEDROCK` is set but empty in your env, unset
it — otherwise the AWS SDK picks bearer auth over SigV4 and Bedrock calls fail
to sign.

## MCP Server — use ThreatForest as an agent tool

The `@threatforest/mcp-server` package exposes ThreatForest as 4 MCP tools that
any AI agent (Claude Code, Cursor, Kiro, or any MCP client) can call.

### Setup

```bash
cd ts
npm install
npm run build:packages       # builds all packages including mcp-server
```

Embeddings run through the **Python ML service**, which is the supported backend
(it honours `embeddings.model`, so alternative embedders such as ThreatBERT work).
Start it before using the MCP server:

```bash
python -m ml_service            # binds 127.0.0.1:8770
```

The engine pre-flights this service and refuses to start a run when it is
unreachable, rather than producing a "complete" threat model with silently
missing attack paths.

### Add to Claude Code

Add to `~/.claude.json` (global) or `.claude/mcp.json` (project-local):

```json
{
  "mcpServers": {
    "threatforest": {
      "command": "node",
      "args": [
        "/absolute/path/to/ts/packages/mcp-server/dist/main.js",
        "/absolute/path/to/repo-root"
      ]
    }
  }
}
```

The second arg points to the repo root (where `.threatforest/config.yaml` lives).
No `env` block is needed — the engine defaults to the Python ML service.

### Tools

| Tool | Description |
|------|-------------|
| `threatforest_scan` | Start a threat model scan against a project path (returns `run_id` immediately) |
| `threatforest_get_run` | Poll status, progress %, current stage, and summary when complete |
| `threatforest_list_runs` | List all active and recently completed scans |
| `threatforest_get_findings` | Retrieve full structured attack trees, MITRE TTP mappings, and mitigations |

### Strands agent integration

For direct use inside a Strands agent (no MCP needed):

```typescript
import { makeScanTool, makeGetRunTool, makeGetFindingsTool } from '@threatforest/mcp-server/strands';

const agent = new Agent({
  tools: [makeScanTool(), makeGetRunTool(), makeGetFindingsTool()],
});
```

### Example prompts

- "Scan /path/to/my/project for security threats"
- "What threats were found in run abc123?"
- "List my recent scans"

Scans run 5-30 minutes depending on project size. The agent starts a scan,
polls progress, then retrieves structured findings (attack trees with MITRE
ATT&CK technique mappings and mitigation recommendations).

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
