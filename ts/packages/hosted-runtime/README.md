# ThreatForest Hosted Runtime

AgentCore-compatible HTTP runtime and durable stage-boundary executor.

Build the ARM64 image from the repository root:

```sh
docker buildx build \
  --platform linux/arm64 \
  -f ts/packages/hosted-runtime/Dockerfile \
  -t threatforest-hosted-runtime .
```

Required runtime environment:

- `AWS_REGION`
- `THREATFOREST_STATE_TABLE`
- `THREATFOREST_ARTIFACT_BUCKET`
- `THREATFOREST_ARTIFACT_KMS_KEY_ARN`
- `THREATFOREST_ACTOR_HMAC_KEY_ARN`
- `THREATFOREST_MEMORY_ID`

Optional environment:

- `THREATFOREST_STATE_TABLE_APPLICATION_INDEX` (default `GSI1`)
- `THREATFOREST_ARTIFACT_KEY_PREFIX` (default `hosted`)
- `THREATFOREST_PRINCIPAL_MODE` (`runtime_user_id` by default)
- `THREATFOREST_COGNITO_USER_POOL_ID` and `THREATFOREST_COGNITO_CLIENT_ID`
  (required only when `THREATFOREST_PRINCIPAL_MODE=cognito_jwt`)
- `THREATFOREST_COGNITO_TOKEN_USE` (`access` by default)
- `THREATFOREST_WORKSPACE_ROOT` (default `/tmp/threatforest-ingestion`)
- `THREATFOREST_SHUTDOWN_GRACE_MS` (default `25000`)
- `HOST` and `PORT` (defaults `0.0.0.0:8080`)

Production materializes ready normalized ingestion objects from the encrypted
artifact bucket into isolated owner/application/run snapshots beneath
`THREATFOREST_WORKSPACE_ROOT`. Engine state is preserved under the
corresponding run directory. Verified report outputs are published back to the
encrypted artifact bucket and registered as hosted application versions.
Authoritative threat inputs identified during ingestion are forwarded to every
engine stage through the graph's authoritative-input option.

The server exposes unauthenticated `GET /ping` for AgentCore health checks.
Every invocation resolves the AgentCore-provided runtime user ID by default;
direct Cognito JWT verification remains available as an explicit compatibility
mode.
