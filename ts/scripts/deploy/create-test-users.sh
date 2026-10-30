#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# shellcheck source=common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

validate_aws_identity
require_command jq
require_env TF_TEST_USER_A_EMAIL
require_env TF_TEST_USER_A_PASSWORD
require_env TF_TEST_USER_B_EMAIL
require_env TF_TEST_USER_B_PASSWORD

user_pool_id="${TF_USER_POOL_ID:-$(stack_resource ThreatForestIdentity AWS::Cognito::UserPool UserPool)}"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/threatforest-users.XXXXXX")"
trap 'rm -rf -- "${temporary_directory}"' EXIT

ensure_user() {
  local label="$1"
  local username="$2"
  local email="$3"
  local password="$4"

  if aws_regional cognito-idp admin-get-user \
    --user-pool-id "${user_pool_id}" \
    --username "${username}" >/dev/null 2>&1; then
    log "Cognito test user ${label} already exists; updating its permanent password."
  else
    log "Creating Cognito test user ${label}."
    aws_regional cognito-idp admin-create-user \
      --user-pool-id "${user_pool_id}" \
      --username "${username}" \
      --message-action SUPPRESS \
      --user-attributes \
        "Name=email,Value=${email}" \
        'Name=email_verified,Value=true' >/dev/null
  fi

  local password_request="${temporary_directory}/${label}-password.json"
  jq -n \
    --arg pool "${user_pool_id}" \
    --arg user "${username}" \
    --arg password "${password}" \
    '{UserPoolId:$pool,Username:$user,Password:$password,Permanent:true}' \
    >"${password_request}"
  aws_regional cognito-idp admin-set-user-password \
    --cli-input-json "file://${password_request}"
  rm -f -- "${password_request}"

  aws_regional cognito-idp admin-get-user \
    --user-pool-id "${user_pool_id}" \
    --username "${username}" \
    --query "UserAttributes[?Name=='sub'].Value | [0]" \
    --output text
}

user_a_username="${TF_TEST_USER_A_USERNAME:-${TF_TEST_USER_A_EMAIL}}"
user_b_username="${TF_TEST_USER_B_USERNAME:-${TF_TEST_USER_B_EMAIL}}"
user_a_sub="$(ensure_user user-a "${user_a_username}" "${TF_TEST_USER_A_EMAIL}" "${TF_TEST_USER_A_PASSWORD}")"
user_b_sub="$(ensure_user user-b "${user_b_username}" "${TF_TEST_USER_B_EMAIL}" "${TF_TEST_USER_B_PASSWORD}")"

printf 'TF_TEST_USER_A_SUB=%q\nTF_TEST_USER_B_SUB=%q\n' "${user_a_sub}" "${user_b_sub}"
log 'Created or updated both Cognito test users. Passwords were not written to repository files.'
