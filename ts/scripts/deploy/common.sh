#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly TS_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/../.." && pwd -P)"
readonly REPOSITORY_ROOT="$(cd -- "${TS_ROOT}/.." && pwd -P)"
readonly INFRA_DIRECTORY="${TS_ROOT}/packages/infra"

export AWS_PAGER=''
export AWS_CLI_AUTO_PROMPT='off'

log() {
  printf '[threatforest] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Required command is not installed: $1"
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "Required environment variable is not set: ${name}"
}

require_file() {
  [[ -f "$1" ]] || die "Required file does not exist: $1"
}

require_directory() {
  [[ -d "$1" ]] || die "Required directory does not exist: $1"
}

# Resolve defaults in the same module that CDK uses. Do not force a named
# profile: the AWS credential chain also supports SSO, assumed roles and CI.
require_command node
require_command jq
deployment_config="$(node --input-type=module - "${INFRA_DIRECTORY}/src/deployment-config.mjs" <<'JS'
import { pathToFileURL } from 'node:url';
const { resolveDeployment } = await import(pathToFileURL(process.argv[2]).href);
console.log(JSON.stringify(resolveDeployment()));
JS
)"
export TF_ACCOUNT_ID="$(jq -r .account <<<"${deployment_config}")"
export TF_REGION="$(jq -r .region <<<"${deployment_config}")"
export TF_EDGE_REGION="$(jq -r .edgeRegion <<<"${deployment_config}")"
export TF_ENVIRONMENT="$(jq -r .environment <<<"${deployment_config}")"
export TF_NAME_PREFIX="$(jq -r .namePrefix <<<"${deployment_config}")"
unset deployment_config
export AWS_REGION="${TF_REGION}"
export AWS_DEFAULT_REGION="${TF_REGION}"
AWS_PROFILE_ARGS=()
if [[ -n "${AWS_PROFILE:-}" ]]; then
  AWS_PROFILE_ARGS=(--profile "${AWS_PROFILE}")
fi

aws_region() {
  local region="$1"
  shift
  aws --no-cli-pager ${AWS_PROFILE_ARGS[@]+"${AWS_PROFILE_ARGS[@]}"} --region "${region}" "$@"
}

aws_regional() {
  aws_region "${TF_REGION}" "$@"
}

aws_edge() {
  aws_region "${TF_EDGE_REGION}" "$@"
}

validate_aws_identity() {
  require_command aws
  local account
  account="$(aws_regional sts get-caller-identity --query Account --output text)"
  [[ "${account}" =~ ^[0-9]{12}$ ]] || die 'AWS STS did not return a valid account ID.'
  [[ -z "${TF_ACCOUNT_ID}" || "${account}" == "${TF_ACCOUNT_ID}" ]] ||
    die "AWS credentials resolve to account ${account}, expected ${TF_ACCOUNT_ID}"
  export TF_ACCOUNT_ID="${account}"
  log "Validated AWS account ${account} via ${AWS_PROFILE:-the default credential chain}; region ${TF_REGION}, environment ${TF_ENVIRONMENT}."
}

stack_exists() {
  local stack_name="$1"
  local region="${2:-${TF_REGION}}"
  aws_region "${region}" cloudformation describe-stacks \
    --stack-name "${stack_name}" >/dev/null 2>&1
}

stack_output() {
  local stack_name="$1"
  local output_key="$2"
  local region="${3:-${TF_REGION}}"
  aws_region "${region}" cloudformation describe-stacks \
    --stack-name "${stack_name}" \
    --query "Stacks[0].Outputs[?OutputKey=='${output_key}'].OutputValue | [0]" \
    --output text
}

stack_resource() {
  local stack_name="$1"
  local resource_type="$2"
  local logical_fragment="${3:-}"
  local region="${4:-${TF_REGION}}"
  local query
  if [[ -n "${logical_fragment}" ]]; then
    query="StackResources[?ResourceType=='${resource_type}' && contains(LogicalResourceId, '${logical_fragment}')].PhysicalResourceId"
  else
    query="StackResources[?ResourceType=='${resource_type}'].PhysicalResourceId"
  fi

  local result
  result="$(aws_region "${region}" cloudformation describe-stack-resources \
    --stack-name "${stack_name}" \
    --query "${query}" \
    --output text)"
  [[ -n "${result}" && "${result}" != 'None' ]] ||
    die "Could not discover ${resource_type} (${logical_fragment:-any}) in ${stack_name}"
  [[ "${result}" != *$'\t'* ]] ||
    die "Resource lookup was ambiguous for ${resource_type} (${logical_fragment:-any}) in ${stack_name}: ${result}"
  printf '%s\n' "${result}"
}

load_deployment_outputs() {
  local output_file="${TF_DEPLOYMENT_ENV_FILE:-${TS_ROOT}/packages/deployed-tests/.env.deployed}"
  [[ -f "${output_file}" ]] || die "Deployment outputs not found at ${output_file}; run collect-outputs.sh first"
  set -a
  # shellcheck disable=SC1090
  source "${output_file}"
  set +a
}

cdk() {
  (
    cd "${INFRA_DIRECTORY}"
    npx --no-install cdk "$@" ${AWS_PROFILE_ARGS[@]+"${AWS_PROFILE_ARGS[@]}"}
  )
}
