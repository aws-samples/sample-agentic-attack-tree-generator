# syntax=docker/dockerfile:1.7
# ThreatForest API server — Fargate image.
# Multi-stage build: compile deps in `builder`, ship only the venv + app in `runtime`.

ARG PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.12-slim-bookworm

# -----------------------------------------------------------------------------
# Builder — installs Python deps and pre-downloads the ATTACK-BERT model.
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    HF_HOME=/opt/models \
    TRANSFORMERS_CACHE=/opt/models \
    HF_HUB_DISABLE_TELEMETRY=1 \
    TQDM_DISABLE=1 \
    TOKENIZERS_PARALLELISM=false \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git \
      build-essential \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv==0.5.11 && uv venv "${VIRTUAL_ENV}"

WORKDIR /app

COPY pyproject.toml ./
RUN uv pip compile pyproject.toml -o /tmp/requirements.txt \
 && uv pip install --no-cache -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

COPY src/ ./src/
COPY README.md ./
RUN uv pip install --no-cache --no-deps .

RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('basel/ATTACK-BERT')"

# -----------------------------------------------------------------------------
# Runtime — minimal image that only contains what's needed to serve traffic.
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/opt/models \
    TRANSFORMERS_CACHE=/opt/models \
    HF_HUB_DISABLE_TELEMETRY=1 \
    TQDM_DISABLE=1 \
    TOKENIZERS_PARALLELISM=false \
    THREATFOREST_BACKEND=aws \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 1000 appuser \
 && useradd --uid 1000 --gid 1000 --shell /sbin/nologin --no-create-home appuser

COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv
COPY --from=builder --chown=appuser:appuser /opt/models /opt/models
COPY --from=builder --chown=appuser:appuser /app /app

WORKDIR /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
