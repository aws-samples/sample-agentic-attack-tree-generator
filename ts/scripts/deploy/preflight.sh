#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# shellcheck source=common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

require_command node
require_command npm
require_command npx
require_command jq
require_command aws
require_file "${TS_ROOT}/package.json"
require_file "${TS_ROOT}/package-lock.json"
require_file "${INFRA_DIRECTORY}/cdk.json"
require_file "${REPOSITORY_ROOT}/ts/packages/hosted-runtime/Dockerfile"
require_file "${REPOSITORY_ROOT}/src/ml_service/Dockerfile"

node_major="$(node -p 'Number(process.versions.node.split(".")[0])')"
[[ "${node_major}" -ge 20 ]] || die "Node.js 20 or newer is required; found $(node --version)"

if [[ "${TF_SKIP_DOCKER_CHECK:-0}" != '1' ]]; then
  require_command docker
  docker info >/dev/null 2>&1 ||
    die "Docker daemon is unavailable. Start Docker or set TF_SKIP_DOCKER_CHECK=1 for non-container checks."
  docker buildx version >/dev/null 2>&1 ||
    die "Docker buildx is required for the ARM64 Runtime and AMD64 mapper images."
fi

if [[ "${TF_SKIP_AWS_CHECK:-0}" != '1' ]]; then
  validate_aws_identity
  aws_regional cloudformation list-stacks --max-items 1 >/dev/null
  aws_edge cloudformation list-stacks --max-items 1 >/dev/null
  aws_regional ecr describe-repositories --max-results 1 >/dev/null
  aws_regional cognito-idp list-user-pools --max-results 1 >/dev/null
  # Two 4-vCPU mapper tasks plus one replacement during a rolling deployment.
  # Existing workloads and autoscaling need additional headroom.
  fargate_quota="$(aws_regional service-quotas get-service-quota \
    --service-code fargate --quota-code L-3032A538 --output json)"
  jq -e '.Quota.Value >= 12' <<<"${fargate_quota}" >/dev/null ||
    die "Fargate On-Demand vCPU quota in ${TF_REGION} must be at least 12 for deployment (plus headroom for other workloads). Request an increase for quota L-3032A538, then rerun."
fi

if [[ "${TF_REQUIRE_WEB_BUILD:-0}" == '1' ]]; then
  require_file "${TS_ROOT}/web/out/index.html"
fi

log "Preflight checks passed for ${TF_ACCOUNT_ID}/${TF_REGION} (edge ${TF_EDGE_REGION})."
