# syntax=docker/dockerfile:1.7
# ThreatForest API server — Fargate image.
FROM public.ecr.aws/docker/library/python:3.12-slim-bookworm

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
    THREATFOREST_BACKEND=aws \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:/root/.local/bin:${PATH}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git \
      curl \
      build-essential \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv==0.5.11 && uv venv "${VIRTUAL_ENV}"

WORKDIR /app

# --- Install dependencies (cached layer — changes only when pyproject.toml does) ---
COPY pyproject.toml ./
RUN uv pip compile pyproject.toml -o /tmp/requirements.txt \
 && uv pip install --no-cache -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# --- Install the application itself ---
COPY src/ ./src/
COPY README.md ./
RUN uv pip install --no-cache --no-deps .

# --- Pre-bake the ATTACK-BERT embedding model so first request is fast ---
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('basel/ATTACK-BERT')"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
