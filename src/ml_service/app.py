"""FastAPI app for the ThreatForest ML/MITRE service.

Endpoints (the seam the TS TTP stage calls):
    GET  /health                 — liveness + warm-state probe
    POST /embed   {texts[]}       -> {vectors: float[][]}
    POST /match_steps {steps[], ...} -> {results: [{attack_step, matches[]}]}

`/match_steps` delegates to the existing ``TTCMatcher`` so the AWS-term boost,
cross-framework merge, and top-k ranking are byte-for-byte identical to the
in-process pipeline — this service is a transport wrapper, not a reimplementation.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

# Disable HF Hub telemetry before any sentence-transformers import path runs
# (mirrors embedding_service.py / cli.py — avoids background-thread timeouts).
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")

logger = logging.getLogger("ml_service")


# --------------------------------------------------------------------------- #
# Request / response models (thin Pydantic contract — mirrored as Zod in TS)
# --------------------------------------------------------------------------- #
class EmbedRequest(BaseModel):
    texts: list[str] = Field(default_factory=list)


class EmbedResponse(BaseModel):
    vectors: list[list[float]]


class MatchStepsRequest(BaseModel):
    steps: list[str] = Field(default_factory=list)
    top_k: int = 3
    # When omitted, the matcher falls back to config.ttc_threshold (same as the
    # in-process call site in agents/ttp/embedding.py).
    min_similarity: Optional[float] = None
    # None => all frameworks defined in config (matches TTCMatcher default).
    frameworks: Optional[list[str]] = None


class TechniqueMatch(BaseModel):
    technique_id: str
    name: str
    description: str
    kill_chain_phases: list[str]
    similarity: float
    confidence: str
    framework: str


class StepMatch(BaseModel):
    attack_step: str
    matches: list[TechniqueMatch]


class MatchStepsResponse(BaseModel):
    results: list[StepMatch]


# --------------------------------------------------------------------------- #
# Warm singletons — model + STIX graphs load once per (frameworks, threshold).
# --------------------------------------------------------------------------- #
def _default_threshold() -> float:
    from threatforest.config import config

    return config.ttc_threshold


@lru_cache(maxsize=8)
def _get_matcher(frameworks_key: Optional[tuple[str, ...]], min_similarity: float):
    """Return a cached, initialized TTCMatcher.

    Cached on (frameworks tuple, threshold) so repeated requests reuse the loaded
    embedding model and STIX vector indexes. ``lru_cache`` requires hashable args,
    hence the frameworks tuple.
    """
    from threatforest.modules.workflow.ttc_mappings.matcher import TTCMatcher

    frameworks = list(frameworks_key) if frameworks_key is not None else None
    matcher = TTCMatcher(min_similarity=min_similarity, frameworks=frameworks)
    # Force eager load so the first real request isn't penalized and /health can
    # report readiness.
    matcher._ensure_initialized()  # noqa: SLF001 — intentional warm-up
    return matcher


@lru_cache(maxsize=1)
def _get_embedding_service():
    from threatforest.config import config
    from threatforest.embedding.service import EmbeddingService

    svc = EmbeddingService(config.embeddings_model)
    svc._load_model()  # noqa: SLF001 — eager warm-up
    return svc


def create_app(*, warm: bool = False) -> FastAPI:
    """Build the ML-service FastAPI app.

    Args:
        warm: when True, eagerly load the default matcher + embedding model at
            construction time so the process is ready before serving traffic.
    """
    app = FastAPI(title="ThreatForest ML Service")

    @app.on_event("startup")
    async def _startup() -> None:  # pragma: no cover - exercised at runtime
        if warm:
            logger.info("Warming ML service (loading embedding model + STIX graphs)...")
            _get_embedding_service()
            _get_matcher(None, _default_threshold())
            logger.info("ML service warm.")

    @app.get("/health")
    async def health() -> dict[str, object]:
        return {
            "status": "ok",
            "embedding_model_loaded": _get_embedding_service.cache_info().currsize > 0,
            "matchers_loaded": _get_matcher.cache_info().currsize,
        }

    @app.post("/embed", response_model=EmbedResponse)
    async def embed(req: EmbedRequest) -> EmbedResponse:
        svc = _get_embedding_service()
        vectors = svc.get_batch_embeddings(req.texts, show_progress=False)
        return EmbedResponse(vectors=vectors)

    @app.post("/match_steps", response_model=MatchStepsResponse)
    async def match_steps(req: MatchStepsRequest) -> MatchStepsResponse:
        threshold = req.min_similarity if req.min_similarity is not None else _default_threshold()
        fw_key = tuple(req.frameworks) if req.frameworks is not None else None
        matcher = _get_matcher(fw_key, threshold)
        raw = matcher.match_steps(req.steps, top_k=req.top_k)
        # `raw` is already in the {attack_step, matches:[...]} shape; Pydantic
        # validates/normalizes it into the response model.
        return MatchStepsResponse(results=raw)

    return app


app = create_app(warm=False)
