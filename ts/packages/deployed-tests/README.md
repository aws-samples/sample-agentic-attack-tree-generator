# ThreatForest Deployed Tests

These tests are black-box probes for the deployment selected by `.env.deployed`.
AWS checks validate the collected `TF_ACCOUNT_ID`, region, and environment;
they do not assume the original deployment account or a personal AWS profile.
They use Node built-ins only and are skipped unless explicitly enabled.

```bash
source .env.deployed
export TF_RUN_DEPLOYED_TESTS=1
export TF_TEST_USER_A_ACCESS_TOKEN='...'
export TF_TEST_USER_B_ACCESS_TOKEN='...'
npm test
```

`collect-outputs.sh` creates `.env.deployed`. Access tokens are intentionally
not collected or persisted. Obtain short-lived Cognito access tokens through
the deployed PKCE login and pass them in the environment.

The token helper drives that real browser flow for both test users and writes
the tokens to a mode-`0600` temporary file:

```bash
export TF_TEST_USER_A_USERNAME='...'
export TF_TEST_USER_A_PASSWORD='...'
export TF_TEST_USER_B_USERNAME='...'
export TF_TEST_USER_B_PASSWORD='...'
npm run tokens
source /tmp/threatforest-deployed-test-tokens.env
```

The long-running agent workflow also requires:

```bash
export TF_RUN_AGENT_HITL_TEST=1
```

Preserve the completed application and write its run, upload, and artifact IDs
for the fixture-dependent MCP, WebSocket, encryption, Memory, and Evaluation
probes:

```bash
export TF_PRESERVE_AGENT_FIXTURE=1
node --test --test-concurrency=1 test/agent-hitl.test.mjs
source /tmp/threatforest-agent-hitl-fixture.env
```

Optional stricter checks:

- `TF_TEST_RUN_ID`: exercise WebSocket replay, run-correlated logs, MCP run
  reads, and pending-HITL listing.
- `TF_MCP_HITL_ACTION=respond|skip`: mutate one pending interaction from
  `TF_TEST_RUN_ID` through MCP. `TF_MCP_HITL_INTERACTION_ID` selects a specific
  pending interaction; otherwise the first is used. For `respond`, optional
  `TF_MCP_HITL_RESPONSE_TEXT` replaces the default acceptance response.
- `TF_MCP_TEST_APPLICATION_ID` and `TF_MCP_TEST_SOURCE_ARTIFACT_IDS`: start,
  replay, inspect, and stop an MCP run using an existing application and a
  comma-separated set of ready artifact IDs.
- `TF_REQUIRE_RUN_TELEMETRY=1`: require Memory and Evaluation log matches.
  The probe also requires the run's exact completion span in the shared
  `aws/spans` group. Evaluation polling allows twenty minutes for the
  five-minute AgentCore session timeout and asynchronous evaluator processing.
- `TF_RUN_BATCH_EVALUATION_TEST=1`: start and poll a batch evaluation that
  inherits the Online Evaluation source and evaluator set, while requiring the
  live telemetry customer KMS key. Run this within two hours of a successful
  Online Evaluation probe. `TF_BATCH_EVALUATION_ID` resumes polling an existing
  diagnostic instead of creating another one.
- `TF_TEST_ARTIFACT_KEY`: verify SSE-KMS metadata on a specific uploaded object.
- `TF_RUN_MEMORY_REUSE_TEST=1`: start and complete a second run in the same
  user/application Memory scope. This verifies the reuse path remains
  operational, but does not by itself prove that retrieved context changed the
  model output.

The agent test creates an application, uploads a Markdown fixture, exercises
both submit and skip HITL responses, waits for completion, validates published
threat, attack-tree, accepted TTP mapping, mitigation, and evidence structure,
and checks report download integrity. It deletes the application in cleanup
unless `TF_PRESERVE_AGENT_FIXTURE=1` is set.
