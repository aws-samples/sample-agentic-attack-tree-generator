#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# shellcheck source=common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

validate_aws_identity
require_env TF_ADMIN_EMAIL
[[ "${TF_ADMIN_EMAIL}" == *@*.* ]] || die 'TF_ADMIN_EMAIL must be an email address.'
user_pool_id="$(stack_resource ThreatForestIdentity AWS::Cognito::UserPool UserPool)"

# Listing first avoids treating permission or connectivity failures as a
# missing user. Never reset an existing user's password during redeployment.
users="$(aws_regional cognito-idp list-users --user-pool-id "${user_pool_id}" --output json)"
if jq -e --arg email "${TF_ADMIN_EMAIL}" \
  '.Users[] | select(.Username == $email or any(.Attributes[]; .Name == "email" and .Value == $email))' \
  <<<"${users}" >/dev/null; then
  log 'The requested user already exists; their credentials are unchanged.'
else
  aws_regional cognito-idp admin-create-user \
    --user-pool-id "${user_pool_id}" \
    --username "${TF_ADMIN_EMAIL}" \
    --desired-delivery-mediums EMAIL \
    --user-attributes "Name=email,Value=${TF_ADMIN_EMAIL}" >/dev/null
  log "Cognito sent a temporary-password invitation to ${TF_ADMIN_EMAIL}. Sign in at the deployed application to choose a password."
fi
