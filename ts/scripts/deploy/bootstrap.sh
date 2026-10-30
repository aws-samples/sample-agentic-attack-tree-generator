#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# shellcheck source=common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

validate_aws_identity
require_command npx
require_command npm

if [[ "${TF_SKIP_INSTALL:-0}" != '1' ]]; then
  npm ci --prefix "${TS_ROOT}"
fi

bootstrap_region() {
  local region="$1"
  log "Bootstrapping CDK in ${TF_ACCOUNT_ID}/${region}."
  (
    cd "${INFRA_DIRECTORY}"
    AWS_REGION="${region}" AWS_DEFAULT_REGION="${region}" npx --no-install cdk bootstrap \
      "aws://${TF_ACCOUNT_ID}/${region}" \
      ${AWS_PROFILE_ARGS[@]+"${AWS_PROFILE_ARGS[@]}"} \
      --tags Application=ThreatForest \
      --tags "Environment=${TF_ENVIRONMENT}" \
      --tags ManagedBy=CDK \
      --termination-protection
  )
}

bootstrap_region "${TF_REGION}"
if [[ "${TF_EDGE_REGION}" != "${TF_REGION}" ]]; then
  bootstrap_region "${TF_EDGE_REGION}"
fi
log 'CDK bootstrap completed in both required regions.'
