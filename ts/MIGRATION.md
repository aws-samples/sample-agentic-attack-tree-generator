# TypeScript migration status

The TypeScript engine is the active pipeline for both local and hosted execution.
The old Python agent pipeline and experimental TypeScript embedding backend have
been removed. `TF_USE_PYTHON_ML` is not a supported switch.

| Responsibility | Current implementation |
| --- | --- |
| Agents, tools, validation, report generation | `packages/engine` |
| Contracts | `packages/types` |
| Local API, CLI, MCP | `packages/server`, `packages/cli`, `packages/mcp-server` |
| Hosted lifecycle and recovery | `packages/control-plane`, `packages/hosted-runtime` |
| Hosted API and source normalization | `packages/hosted-api`, `packages/ingestion` |
| Dashboard | `web` (Next.js static export) |
| Embeddings and framework matching | `../src/ml_service` and `../src/threatforest/modules/graph` |
| Infrastructure and acceptance | `packages/infra`, `packages/deployed-tests` |

Historical Python report fixtures remain compatibility checks. They do not
establish model accuracy. Current risk scoring intentionally differs from the old
probability fixture: merely recommending a mitigation cannot reduce current risk.
Provider output contracts are enforced by application-owned storage tools.

See [README](README.md) for current commands, the
[repository review](../docs/repository-review-2026-09-16.md) for findings, and the
[improvement record](../docs/improvements-2026-09-17.md) for follow-up changes and
remaining empirical validation. Hosted request, response, exposed reasoning,
and tool logs appear in both the live stream and historical run logs.
