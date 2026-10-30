#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# shellcheck source=common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

validate_aws_identity
require_command jq
require_env TF_PROVIDER
require_env TF_PROVIDER_API_KEY
require_env TF_PROVIDER_USERNAME

provider="$(printf '%s' "${TF_PROVIDER}" | tr '[:upper:]' '[:lower:]')"
case "${provider}" in
  anthropic | openai | gemini) ;;
  *) die 'TF_PROVIDER must be one of: anthropic, openai, gemini' ;;
esac

user_pool_id="${TF_USER_POOL_ID:-$(stack_resource ThreatForestIdentity AWS::Cognito::UserPool UserPool)}"
owner_id="$(aws_regional cognito-idp admin-get-user \
  --user-pool-id "${user_pool_id}" \
  --username "${TF_PROVIDER_USERNAME}" \
  --query "UserAttributes[?Name=='sub'].Value | [0]" \
  --output text)"
[[ -n "${owner_id}" && "${owner_id}" != 'None' ]] ||
  die "Could not resolve a Cognito sub for ${TF_PROVIDER_USERNAME}"

secret_name="threatforest/${TF_ENVIRONMENT}/users/${owner_id}/providers/${provider}"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/threatforest-provider.XXXXXX")"
trap 'rm -rf -- "${temporary_directory}"' EXIT
secret_payload="${temporary_directory}/secret.json"
request_payload="${temporary_directory}/request.json"
jq -n --arg api_key "${TF_PROVIDER_API_KEY}" '{apiKey:$api_key}' >"${secret_payload}"

if aws_regional secretsmanager describe-secret --secret-id "${secret_name}" >/dev/null 2>&1; then
  jq -n \
    --arg id "${secret_name}" \
    --rawfile value "${secret_payload}" \
    '{SecretId:$id,SecretString:$value}' >"${request_payload}"
  aws_regional secretsmanager put-secret-value \
    --cli-input-json "file://${request_payload}" >/dev/null
  log "Updated ${provider} credential for Cognito user ${TF_PROVIDER_USERNAME}."
else
  jq -n \
    --arg name "${secret_name}" \
    --arg environment "${TF_ENVIRONMENT}" \
    --arg description "ThreatForest ${provider} API credential for one Cognito principal" \
    --rawfile value "${secret_payload}" \
    '{Name:$name,Description:$description,SecretString:$value,Tags:[
      {Key:"Application",Value:"ThreatForest"},
      {Key:"Environment",Value:$environment},
      {Key:"ManagedBy",Value:"deployment-script"}
    ]}' >"${request_payload}"
  aws_regional secretsmanager create-secret \
    --cli-input-json "file://${request_payload}" >/dev/null
  log "Created ${provider} credential for Cognito user ${TF_PROVIDER_USERNAME}."
fi

log "Secret path: ${secret_name}. Secret value was supplied only through a mode-0600 temporary file."
