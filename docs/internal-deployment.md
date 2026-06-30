# ThreatForest — Internal AWS Deployment

Status of the internal deployment (frontend on Harmony, backend on Fargate in
Amazon-owned accounts) and what needs to happen next.

## Components

| Component | Location | Status |
|---|---|---|
| Backend engine (FastAPI + Strands pipeline) | `src/threatforest/`, `src/server/` | Local dev works; S3/DDB backend not yet wired |
| Fargate Dockerfile | `src/server/Dockerfile` | Merged on `mainline` |
| Harmony UI | `ThreatForestUI` Brazil package | Deployed to Harmony beta |
| Infra CDK (VPC/ALB/Fargate/S3/DDB/ECR) | `ThreatForestAppCDK` Brazil package | PR in review |
| Brazil pipeline | Pipeline 9552370, `ThreatForestApp` | Self-mutating; beta deploy blocked on CDK PR |

## Accounts and regions

- All stages (tools/beta/gamma) share account `413612134084`.
- Deployment region: `us-west-2`.
- Pipeline deployment groups:
  - `us-west-2:9552370:betaApplication`
  - `us-west-2:9552370:gammaApplication` (gated on manual approval)

## Harmony frontend

- App URL: https://threatforest.beta.harmony.a2z.com
- Package: https://code.amazon.com/packages/ThreatForestUI
- Bindle (access control): https://bindles.amazon.com/resource/amzn1.bindle.resource.yrvkzgzyafgxzj6sx6bq
- API base URL is injected at build time via `VITE_API_BASE`. `.env.beta`
  currently holds a placeholder — update with the ALB DNS once the backend
  stack deploys, then redeploy:
  ```
  cd src/ThreatForestUI
  harmony app deploy --stage beta
  ```
- All backend calls go through `@amzn/sentry-fetch` so Midway tokens are
  attached automatically (see `src/api-client.js`).
- WebSocket URL is derived from `VITE_API_BASE`, not `window.location`, so
  WS traffic bypasses Harmony's CloudFront 60s idle timeout and hits the
  ALB directly.

## Backend infrastructure (CDK)

`ThreatForestAppCDK/lib/service-stack.ts` provisions, per stage:

- Isolated VPC (no NAT), with interface endpoints for Bedrock Runtime, ECR,
  CloudWatch Logs, Secrets Manager, SSM messages, and gateway endpoints for
  DynamoDB + S3.
- `tf-artifacts-<stage>-<account>` S3 bucket (versioned, KMS-SSE).
- DynamoDB: `tf-runs-<stage>` (pk `run_id`, GSI on status) and
  `tf-applications-<stage>` (pk `app_id`, sk `version_id`).
- Secrets Manager: `tf-langfuse-<stage>` (operator populates public/secret
  keys after first deploy).
- ECR repo `tf-server-<stage>` — image must be built and pushed separately
  (not yet wired into the pipeline).
- Fargate service on X86_64, 2 vCPU / 8 GB, auto-scaling 1–2 (beta) to 2–6
  (prod) on CPU utilisation.
- Internal ALB, HTTP listener on port 80, sticky sessions for WebSocket
  continuity, 120 s idle timeout.
- Container `healthCheck` and ALB target `healthCheck` both hit
  `/api/health`.

### Environment passed to the container

```
THREATFOREST_BACKEND=aws
TF_STAGE=beta|gamma|prod
TF_ARTIFACTS_BUCKET=tf-artifacts-<stage>-<account>
TF_RUNS_TABLE=tf-runs-<stage>
TF_APPS_TABLE=tf-applications-<stage>
AWS_REGION=us-west-2
LANGFUSE_PUBLIC_KEY  # from Secrets Manager
LANGFUSE_SECRET_KEY  # from Secrets Manager
```

The engine still reads config from local filesystem. The `THREATFOREST_BACKEND`
env var is reserved for a future switch to the S3+DynamoDB workspace;
today, containers would need to seed `.threatforest/config.yaml` themselves.

## Remaining work

### Must-land to reach a working beta end-to-end

1. **Merge CR-272271410** (CDK region fix) — so the ThreatForest-beta CFN
   stack synthesizes in `us-west-2`.
2. **Build + push the backend image to `tf-server-beta` ECR.** Either:
   - Manually: `docker build -t tf-server:latest -f src/server/Dockerfile .`
     then push to ECR.
   - Or extend `ThreatForestAppCDK` to add a CodeBuild action that builds
     from the engine package and pushes on each pipeline run.
3. **Request Bedrock model access for Opus 4.7** in the shared account
   `413612134084` (region `us-west-2`). Takes 1–2 weeks end-to-end.
4. **Populate the Langfuse secret** via the Secrets Manager console
   (`tf-langfuse-beta`). Engine will refuse to start without it.
5. **Capture the beta ALB DNS** from the stack outputs and update
   `src/ThreatForestUI/.env.beta` → redeploy UI.
6. **Grant the team access** on the Harmony bindle
   `amzn1.bindle.resource.yrvkzgzyafgxzj6sx6bq` (POSIX group, not aliases).

### Engine changes required before the backend is actually usable in AWS

These are gated on a `THREATFOREST_BACKEND=aws` switch and do not affect
local dev.

- **Workspace protocol + `LocalFilesystemWorkspace` + `S3Workspace`** —
  replaces every `open(state_dir / "...")` in `src/threatforest/agents/*/`
  with `workspace.read_state(key)` / `workspace.write_state(key, bytes)`.
  Currently the engine expects `.threatforest/runs/<slug>/<ts>/` on local
  disk.
- **`RunStore` protocol** — moves `RunManager.active_runs`,
  `_event_history`, `_controls`, `_pending_interactions` out of process
  memory into DynamoDB so scale-in/out does not lose runs.
- **Application registry on DynamoDB** — `src/server/registry.py` needs a
  `DynamoApplicationRegistry` implementation (today it reads files from
  disk).
- **Repo ingestion endpoints** — the native OS directory picker does not
  work on Fargate. Add:
  - `POST /api/runs/ingest/git` — `git clone <url>` into a scratch dir.
  - `POST /api/runs/ingest/upload` — presigned S3 PUT for a `.zip`, then
    unpack.
- **Drop `AWS_PROFILE` env handling** in `src/threatforest/modules/core/providers/bedrock.py`
  when `THREATFOREST_BACKEND=aws` — rely on the Fargate task role.

### Nice-to-haves

- Trim the Docker image (torch + sentence-transformers + model cache ≈ 4 GB)
  using a multi-stage build. CPU-only torch drops ~1.5 GB.
- Wire the Dockerfile build into the Brazil pipeline via a CodeBuild
  action that pushes to `tf-server-<stage>` ECR per stage.
- Add CloudWatch alarms (5xx rate, task health, DDB throttles) piped to
  Sim tickets via `@amzn/sim-ticket-cdk-constructs`.

## Operational notes

- Pipeline URL: https://pipelines.amazon.com/pipelines/ThreatForestApp
- Beta CFN stack name (will be): `ThreatForest-beta` in `us-west-2`
- To diagnose a failed beta deploy, open the canonical event in the
  pipeline UI → click through to the CloudFormation events page on the
  deployment account.
- To redeploy just the UI without touching the backend, run
  `harmony app deploy --stage beta` from `src/ThreatForestUI/` — no
  pipeline involvement needed.
- To hotfix the CDK without waiting for a pipeline run, manually
  `cdk deploy --profile tf-beta ThreatForest-beta` from
  `ThreatForestAppCDK/`. But the pipeline will revert it on the next
  canonical event, so land the fix in mainline too.
