# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.11
ARG TORCH_VERSION=2.13.0+cpu

# Graphs and model files are architecture-independent. Build them natively so
# ARM developer machines do not run BERT indexing through x86 emulation.
FROM --platform=$BUILDPLATFORM python:${PYTHON_VERSION}-slim-bookworm AS assets

ARG TORCH_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONPATH=/app/src \
    HF_HOME=/opt/threatforest-assets/huggingface \
    XDG_CACHE_HOME=/opt/threatforest-assets

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ml_service ./src/ml_service
COPY src/threatforest ./src/threatforest
COPY src/ml_service/container-config.yaml /app/.threatforest/config.yaml

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        "torch==${TORCH_VERSION}" \
    && python -m pip install --no-cache-dir . \
    && python -c "from ml_service.app import _default_embedding_model, _get_matcher; _get_matcher(None, _default_embedding_model())"

FROM --platform=$TARGETPLATFORM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG TORCH_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONPATH=/app/src \
    HF_HOME=/home/threatforest/.cache/huggingface \
    XDG_CACHE_HOME=/home/threatforest/.cache \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    TF_ML_HOST=0.0.0.0 \
    TF_ML_PORT=8770 \
    TF_ML_WARM=1

WORKDIR /app

RUN groupadd --gid 10001 threatforest \
    && useradd --uid 10001 --gid 10001 --create-home threatforest

COPY pyproject.toml README.md ./
COPY --chown=10001:10001 src/ml_service ./src/ml_service
COPY --chown=10001:10001 src/threatforest ./src/threatforest

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        "torch==${TORCH_VERSION}" \
    && python -m pip install --no-cache-dir .

COPY --chown=10001:10001 src/ml_service/container-config.yaml /app/.threatforest/config.yaml
COPY --from=assets --chown=10001:10001 /app/.threatforest/graphs /app/.threatforest/graphs
COPY --from=assets --chown=10001:10001 /opt/threatforest-assets/huggingface /home/threatforest/.cache/huggingface

USER 10001:10001

EXPOSE 8770

HEALTHCHECK --interval=30s --timeout=10s --start-period=300s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8770/health', timeout=5).read()" || exit 1

CMD ["python", "-m", "ml_service"]
