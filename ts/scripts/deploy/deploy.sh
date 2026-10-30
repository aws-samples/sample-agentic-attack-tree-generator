#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# shellcheck source=common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

validate_aws_identity
"${SCRIPT_DIRECTORY}/preflight.sh"

if [[ "${TF_SKIP_INSTALL:-0}" != '1' ]]; then
  log 'Installing locked workspace dependencies.'
  npm ci --prefix "${TS_ROOT}"
fi

if [[ "${TF_SKIP_VERIFY:-0}" != '1' ]]; then
  log 'Running the complete hosted verification suite.'
  TF_RUN_DEPLOYED_TESTS=0 TF_RUN_AGENT_HITL_TEST=0 TF_DEPLOYMENT_ENV_FILE=/dev/null \
    npm run verify:hosted --prefix "${TS_ROOT}"
else
  log 'Skipping verification because TF_SKIP_VERIFY=1.'
  npm run build --prefix "${TS_ROOT}"
fi

require_file "${TS_ROOT}/web/out/index.html"

log 'Synthesizing all eight stacks.'
cdk synth --quiet

if [[ "${TF_SKIP_BOOTSTRAP:-0}" != '1' ]]; then
  TF_SKIP_INSTALL=1 "${SCRIPT_DIRECTORY}/bootstrap.sh"
fi

deploy_stacks() {
  log "Deploying stacks: $*"
  cdk deploy "$@" \
    --require-approval never \
    --concurrency "${TF_CDK_CONCURRENCY:-3}" \
    --outputs-file "${TF_CDK_OUTPUTS_FILE:-${TS_ROOT}/packages/deployed-tests/cdk-outputs.json}"
}

deploy_stacks ThreatForestFoundation ThreatForestIdentity ThreatForestWaf
deploy_stacks ThreatForestAgentCore
deploy_stacks ThreatForestServices
deploy_stacks ThreatForestEdge ThreatForestObservability
deploy_stacks ThreatForestEdgeLogging

"${SCRIPT_DIRECTORY}/collect-outputs.sh"
if [[ -n "${TF_ADMIN_EMAIL:-}" ]]; then
  "${SCRIPT_DIRECTORY}/create-user.sh"
fi
log 'ThreatForest deployment completed.'
