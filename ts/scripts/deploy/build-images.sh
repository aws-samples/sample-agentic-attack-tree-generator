#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# shellcheck source=common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

validate_aws_identity
require_command docker
docker info >/dev/null 2>&1 || die 'Docker daemon is unavailable.'
docker buildx version >/dev/null 2>&1 || die 'Docker buildx is required.'

stack_exists ThreatForestFoundation ||
  die 'ThreatForestFoundation must be deployed before publishing images.'

runtime_repository="${TF_RUNTIME_REPOSITORY:-${TF_NAME_PREFIX}-runtime}"
mapper_repository="${TF_MAPPER_REPOSITORY:-${TF_NAME_PREFIX}-mapper}"
image_tag="${TF_IMAGE_TAG:-$(git -C "${REPOSITORY_ROOT}" rev-parse --short=12 HEAD)}"
[[ "${image_tag}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
  die "TF_IMAGE_TAG is not a valid container tag: ${image_tag}"
[[ "${image_tag}" != 'latest' ]] || die 'The immutable repositories do not accept the mutable latest tag.'

registry="${TF_ACCOUNT_ID}.dkr.ecr.${TF_REGION}.amazonaws.com"
aws_regional ecr describe-repositories --repository-names \
  "${runtime_repository}" "${mapper_repository}" >/dev/null
aws_regional ecr get-login-password |
  docker login --username AWS --password-stdin "${registry}"

build_and_push() {
  local repository="$1"
  local platform="$2"
  local dockerfile="$3"
  local image="${registry}/${repository}:${image_tag}"

  if aws_regional ecr describe-images \
    --repository-name "${repository}" \
    --image-ids "imageTag=${image_tag}" >/dev/null 2>&1; then
    log "Image already exists in immutable repository; skipping ${image}."
    return
  fi

  log "Building and pushing ${image} for ${platform}."
  docker buildx build \
    --platform "${platform}" \
    --file "${dockerfile}" \
    --tag "${image}" \
    --provenance=true \
    --sbom=true \
    --push \
    "${REPOSITORY_ROOT}"
}

build_and_push "${runtime_repository}" linux/arm64 \
  "${REPOSITORY_ROOT}/ts/packages/hosted-runtime/Dockerfile"
build_and_push "${mapper_repository}" linux/amd64 \
  "${REPOSITORY_ROOT}/src/ml_service/Dockerfile"

log "Published diagnostic images with immutable tag ${image_tag}."
log 'The current CDK app still deploys content-addressed Docker assets; these tags are for explicit validation and rollback evidence.'
