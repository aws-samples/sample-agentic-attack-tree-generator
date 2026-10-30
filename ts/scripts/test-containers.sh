#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# shellcheck source=deploy/common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/deploy/common.sh"

require_command docker
require_command curl
require_command jq
docker info >/dev/null 2>&1 || die 'Docker daemon is unavailable.'
docker buildx version >/dev/null 2>&1 || die 'Docker buildx is required.'

runtime_image="${TF_RUNTIME_TEST_IMAGE:-threatforest-runtime:test}"
mapper_image="${TF_MAPPER_TEST_IMAGE:-threatforest-mapper:test}"
runtime_container="threatforest-runtime-test-$$"
mapper_container="threatforest-mapper-test-$$"
runtime_port="${TF_RUNTIME_TEST_PORT:-18080}"
mapper_port="${TF_MAPPER_TEST_PORT:-18770}"

cleanup() {
  docker rm -f "${runtime_container}" "${mapper_container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log 'Building AgentCore Runtime test image for Linux ARM64.'
docker buildx build --platform linux/arm64 --load \
  --file "${REPOSITORY_ROOT}/ts/packages/hosted-runtime/Dockerfile" \
  --tag "${runtime_image}" \
  "${REPOSITORY_ROOT}"

log 'Building TTP mapper test image for Linux AMD64.'
docker buildx build --platform linux/amd64 --load \
  --file "${REPOSITORY_ROOT}/src/ml_service/Dockerfile" \
  --tag "${mapper_image}" \
  "${REPOSITORY_ROOT}"

[[ "$(docker image inspect "${runtime_image}" --format '{{.Architecture}}')" == 'arm64' ]] ||
  die 'Runtime image architecture is not arm64.'
[[ "$(docker image inspect "${mapper_image}" --format '{{.Architecture}}')" == 'amd64' ]] ||
  die 'Mapper image architecture is not amd64.'

docker run --detach --rm --name "${runtime_container}" \
  --platform linux/arm64 \
  --publish "127.0.0.1:${runtime_port}:8080" \
  --env AWS_REGION="${TF_REGION}" \
  --env AWS_EC2_METADATA_DISABLED=true \
  --env THREATFOREST_STATE_TABLE=container-test \
  --env THREATFOREST_ARTIFACT_BUCKET=container-test \
  --env THREATFOREST_ARTIFACT_KMS_KEY_ARN=arn:aws:kms:eu-west-2:123456789012:key/00000000-0000-0000-0000-000000000000 \
  --env THREATFOREST_MEMORY_ID=container-test \
  --env THREATFOREST_ACTOR_HMAC_KEY_ARN=arn:aws:kms:eu-west-2:123456789012:key/00000000-0000-0000-0000-000000000000 \
  --env THREATFOREST_MODEL_SECRET_PREFIX=threatforest/test/users \
  "${runtime_image}" >/dev/null

docker run --detach --rm --name "${mapper_container}" \
  --platform linux/amd64 \
  --publish "127.0.0.1:${mapper_port}:8770" \
  --env TF_ML_WARM="${TF_ML_WARM:-0}" \
  "${mapper_image}" >/dev/null

wait_for_json() {
  local url="$1"
  local attempts="$2"
  local delay="$3"
  local output=''
  for ((attempt = 1; attempt <= attempts; attempt += 1)); do
    if output="$(curl --fail --silent --show-error --max-time 10 "${url}" 2>/dev/null)"; then
      jq -e '
        .status
        | strings
        | ascii_downcase
        | . == "healthy" or . == "ok"
      ' <<<"${output}" >/dev/null
      return
    fi
    sleep "${delay}"
  done
  docker logs "${runtime_container}" 2>&1 || true
  docker logs "${mapper_container}" 2>&1 || true
  die "Container did not become healthy: ${url}"
}

wait_for_json "http://127.0.0.1:${runtime_port}/ping" 30 2
wait_for_json "http://127.0.0.1:${mapper_port}/health" 60 5

if [[ "${TF_SKIP_MAPPER_MATCH:-0}" != '1' ]]; then
  response="$(curl --fail --silent --show-error \
    --max-time "${TF_MAPPER_MATCH_TIMEOUT_SECONDS:-900}" \
    --header 'content-type: application/json' \
    --data '{"steps":["An attacker steals an IAM access key and uses it to enumerate S3 buckets."],"frameworks":["attack"],"top_k":3}' \
    "http://127.0.0.1:${mapper_port}/match_steps")"
  jq -e '.results | type == "array" and length == 1' <<<"${response}" >/dev/null ||
    die 'Mapper /match_steps response did not contain one result.'
else
  log 'Skipping mapper inference because TF_SKIP_MAPPER_MATCH=1.'
fi

log 'Runtime /ping, mapper /health, architecture, and mapper inference checks passed.'
