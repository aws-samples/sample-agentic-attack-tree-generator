# Deploy ThreatForest into your AWS account

This repository includes the complete hosted application: the web interface,
Cognito login, API, AgentCore pipeline, Python TTP mapper, storage, workflows,
and operational logs. You do not need resources or credentials from the
original deployment account.

## Before you start

- Use a **commercial AWS account** with permission to deploy CDK/CloudFormation
  stacks and create IAM roles, service-linked roles, networking, containers,
  Bedrock/AgentCore, Cognito, KMS, logging, and the other resources in
  `ts/packages/infra`. Organization policies and permission boundaries must
  permit those resources. The bootstrap execution role uses CDK's default
  administrator policy; use your organization's approved bootstrap if needed.
  Recovery of a failed initial stack also requires permission to disable its
  termination protection and delete it. An explicit deny on
  `cloudformation:UpdateTerminationProtection` requires an authorized operator
  to handle that recovery.
- Install **Node.js 22**, npm, Bash, jq, the AWS CLI v2, and Docker with Buildx.
  Docker must be running and able to build both Linux ARM64 and AMD64 images.
  Python runs inside the mapper container; a local Python environment is not
  required for this deployment.
- Allow build-time downloads from npm, container registries, PyPI/PyTorch,
  Hugging Face, and the framework data sources. The first mapper build downloads
  models and builds its indexes, so it can take substantially longer than
  subsequent builds.
- Use **`eu-west-2` (London)** unless you need another supported region. The
  application requires AgentCore Runtime, Memory, Gateway, Policy, and
  Evaluations. WAF and CloudFront log delivery are always deployed in
  **`us-east-1`**. GovCloud and China partitions are not supported.
- Check Bedrock model access in the destination account. The initial application
  model is `global.anthropic.claude-sonnet-4-5-20250929-v1:0`; the quality evaluator
  uses `global.anthropic.claude-sonnet-4-6`. Complete any required provider
  onboarding and allow the destinations used by their cross-region inference
  profiles. Application settings can select another model after login; the
  evaluator remains a separate Bedrock dependency.
- Allow **at least 12 Fargate On-Demand vCPUs**, plus headroom for other workloads,
  in the application region. Two mapper tasks use 8 vCPUs in total; a rolling
  replacement needs another 4. Autoscaling can use more. The preflight check
  stops before deployment if the applied quota is below 12. Request an increase
  for Fargate quota `L-3032A538` through Service Quotas when necessary.

This is a continuously running hosted deployment. Its baseline includes two NAT
gateways, two mapper tasks (4 vCPUs / 16 GiB each), VPC endpoints, and logging.
Model inference and evaluations add usage charges.

## Deploy

From the root of **this repository**, select credentials for the destination
account. For example, after configuring an AWS CLI SSO profile:

```bash
aws sso login --profile my-target-account
export AWS_PROFILE=my-target-account
export TF_ACCOUNT_ID=123456789012     # replace with your destination account ID
export TF_ADMIN_EMAIL=you@example.com

bash ts/scripts/deploy/deploy.sh
```

`TF_ACCOUNT_ID` is an optional guard: deployment stops if the credentials resolve
to a different account. If omitted, the scripts discover the account through
STS. With no `AWS_PROFILE`, they use the standard AWS credential chain, including
an assumed CI role. No personal profile or account is built into the scripts.

The command:

1. Checks local tools, AWS identity, basic AWS access, and the Fargate quota.
2. Installs locked npm dependencies, builds packages, runs local verification,
   and builds the web application.
3. Synthesizes the infrastructure and bootstraps CDK in both required regions.
4. Builds/publishes container assets and deploys all eight stacks in order.
5. Collects the generated application URL and resource identifiers.
6. Invites `TF_ADMIN_EMAIL` through Cognito when supplied. Existing users keep
   their current passwords.

The scripts run CDK without an interactive IAM approval prompt. Run them only
with the intended deployment credentials.

The application URL is printed at the end. The generated files are:

```text
ts/packages/deployed-tests/.env.deployed
ts/packages/deployed-tests/deployment-outputs.json
ts/packages/deployed-tests/cdk-outputs.json
```

These are local deployment outputs, not credentials. They are ignored by Git.
Redeploying into another account overwrites these files unless you set
`TF_DEPLOYMENT_ENV_FILE`, `TF_DEPLOYMENT_JSON_FILE`, and `TF_CDK_OUTPUTS_FILE`
to separate paths.

## First login and smoke test

Open the printed CloudFront URL. Sign in using the Cognito invitation and set a
new password. The deployment registers the generated CloudFront OAuth callback
and logout URLs automatically; a custom DNS name is not required.

If you omitted the invitation during deployment, run this with the same target
configuration:

```bash
export TF_ADMIN_EMAIL=you@example.com
bash ts/scripts/deploy/create-user.sh
```

In the application:

1. Open settings, select an available model, and test the provider connection.
2. Create an application and upload a small architecture/context document.
3. Start a run, respond to its review prompts, and verify that it completes.
4. Check the live activity stream, historical logs, threat/tree IDs, mitigations,
   and report export.

The automated AWS acceptance suite is documented in
[`ts/packages/deployed-tests/README.md`](../ts/packages/deployed-tests/README.md).
It is deliberately disabled during deployment verification; enable it after
creating test users and collecting tokens for the **new** deployment.

## Configuration and updates

Both the shell scripts and CDK read the same defaults from
[`deployment-config.mjs`](../ts/packages/infra/src/deployment-config.mjs).

| Variable | Default | Purpose |
| --- | --- | --- |
| `AWS_PROFILE` | Standard AWS credential chain | Optional named AWS CLI profile |
| `TF_ACCOUNT_ID` | Discovered through STS | Optional expected account; rejects mismatches |
| `TF_REGION` | `eu-west-2` | Application region; must support all required features |
| `TF_ENVIRONMENT` | `test` | Resource-name prefix and environment tag |
| `TF_ADMIN_EMAIL` | None | Optional first-user invitation |
| `TF_SKIP_BOOTSTRAP` | `0` | Set to `1` when CDK is already bootstrapped by your organization |
| `TF_SKIP_INSTALL` | `0` | Set to `1` only when locked dependencies are already installed |
| `TF_SKIP_VERIFY` | `0` | Set to `1` to skip local tests/typechecks; still builds the application |

To update, rerun `deploy.sh` with the **same account, region, and environment**.
The defaults retain the existing `ThreatForest*` stack names and
`threatforest-test` resource names. For the original installation, select its
AWS profile explicitly; there is no longer a personal default profile.

This package supports **one installation per AWS account**. Environment labels
do not create independent installations: stack names, AgentCore names, and
regional shared tracing settings are intentionally stable. Use separate accounts
for separate installations. Do not change `TF_ENVIRONMENT` on an existing
installation to try to rename it; named resources can be replaced or conflict.

For infrastructure review without deployment, install dependencies, build the
application, and synthesize using an explicit account:

```bash
npm ci --prefix ts
npm run build --prefix ts
export TF_ACCOUNT_ID=123456789012
cd ts/packages/infra
npx --no-install cdk synth
```

Standalone `bootstrap.sh`, `preflight.sh`, and `collect-outputs.sh` are also
available under `ts/scripts/deploy/`. `build-images.sh` is a diagnostic helper;
normal deployment publishes its own content-addressed images automatically.

## Operational notes

- **Failed deployment:** inspect the failing stack event, resolve the specific
  permission, model-access, capacity, or quota issue, and rerun with the same
  target. A stack in `ROLLBACK_COMPLETE` may need its failed stack removed before
  recreation; inspect retained resources first.
- **Account mismatch:** correct `AWS_PROFILE` or the CI role and `TF_ACCOUNT_ID`.
  Changing the guard does not switch credentials.
- **Login issues:** use the CloudFront URL from this deployment's collected
  outputs. An old account's URL or a hand-added alias will not match the generated
  OAuth configuration.
- **Shared observability:** deployment enables Transaction Search and configures
  encryption/retention for shared regional trace log groups such as `aws/spans`.
  These are account-level settings and can affect other tracing workloads.
- **Removal:** stacks have termination protection and retain important data,
  keys, and identity resources. Removing the application is an explicit cleanup
  operation, not an automatic rollback of every resource or charge.

AWS reference documentation:

- [AgentCore feature availability by region](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-regions.html)
- [Fargate quotas](https://docs.aws.amazon.com/general/latest/gr/ecs-service.html)
- [Transaction Search setup and account scope](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Transaction-Search-getting-started.html)

## Validation scope

Validated on 14 October 2026 using a temporary checkout with no pre-existing
dependencies or build outputs:

- Locked dependency installation and the complete `verify:hosted` command
  passed: 392 tests passed (355 Node tests and 37 web tests); 17 AWS acceptance
  tests were intentionally skipped.
- All eight stacks (339 resources) synthesized for two placeholder account IDs:
  `123456789012` / `us-west-2` / `prod`, and
  `210987654321` / `eu-west-2` / `test`. Generated stack targets, Cognito domains,
  runtime regions, and CloudFront encryption policies matched each destination,
  with no original-account or personal-profile references in the templates.
- Shell tests covered profile and CI credentials, account mismatch rejection,
  both bootstrap regions, insufficient Fargate quota, and first-user invitation
  without resetting existing credentials.

No AWS deployment or container build was performed for this portability change.
A successful deployment and completed run in the destination account remain the
acceptance check for its permissions, quotas, model entitlements, and region.
