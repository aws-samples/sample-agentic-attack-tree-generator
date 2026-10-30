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
import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore
from functools import lru_cache
from typing import Optional

from fastapi import FastAPI, HTTPException
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
    texts: list[str] = Field(default_factory=list, max_length=256)


class EmbedResponse(BaseModel):
    vectors: list[list[float]]


class MatchStepsRequest(BaseModel):
    steps: list[str] = Field(default_factory=list, max_length=256)
    top_k: int = Field(default=3, ge=1, le=50)
    # When omitted, the matcher falls back to config.ttc_threshold (same as the
    # in-process call site in agents/ttp/embedding.py).
    min_similarity: Optional[float] = Field(default=None, ge=0, le=1)
    # None => all frameworks defined in config (matches TTCMatcher default).
    frameworks: Optional[list[str]] = None
    # None => the service's local config. Hosted runs always send their durable
    # per-run selection so concurrent users do not share a mutable model choice.
    embedding_model: Optional[str] = None


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
# Warm singletons — model + STIX graphs load once per
# (normalized frameworks, embedding model). One inference worker keeps native
# model/index initialization serial and leaves the HTTP event loop responsive.
# --------------------------------------------------------------------------- #
_inference = ThreadPoolExecutor(max_workers=1, thread_name_prefix="threatforest-inference")
_inference_slots = BoundedSemaphore(8)


async def _infer(work):
    if not _inference_slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="Inference capacity is busy; retry later")
    future = _inference.submit(work)
    future.add_done_callback(lambda _: _inference_slots.release())
    return await asyncio.wrap_future(future)
def _default_threshold() -> float:
    from threatforest.config import config

    return config.ttc_threshold


def _default_embedding_model() -> str:
    from threatforest.config import config

    return config.embeddings_model


@lru_cache(maxsize=16)
def _get_matcher(
    frameworks_key: Optional[tuple[str, ...]],
    embedding_model: str,
):
    """Return a cached, initialized TTCMatcher.

    Cached on (frameworks tuple, embedding model) so repeated requests
    reuse loaded indexes without leaking one run's model selection into another.
    ``lru_cache`` requires hashable args, hence the frameworks tuple.
    """
    from threatforest.modules.workflow.ttc_mappings.matcher import TTCMatcher

    frameworks = list(frameworks_key) if frameworks_key is not None else None
    matcher = TTCMatcher(
        frameworks=frameworks,
        embedding_model=embedding_model,
    )
    # Force eager load so the first real request isn't penalized and /health can
    # report readiness.
    matcher._ensure_initialized()  # noqa: SLF001 — intentional warm-up
    return matcher


@lru_cache(maxsize=1)
def _get_embedding_service():
    from threatforest.config import config
    from threatforest.modules.graph.embedding_service import get_embedding_service
    return get_embedding_service(config.embeddings_model)


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
            await asyncio.get_running_loop().run_in_executor(_inference, _get_embedding_service)
            await asyncio.get_running_loop().run_in_executor(
                _inference, _get_matcher, None, _default_embedding_model())
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
        def infer():
            vectors = _get_embedding_service().get_batch_embeddings(req.texts, show_progress=False)
            if len(vectors) != len(req.texts) or any(not vector for vector in vectors):
                raise RuntimeError("Embedding inference failed")
            return EmbedResponse(vectors=vectors)
        return await _infer(infer)

    @app.post("/match_steps", response_model=MatchStepsResponse)
    async def match_steps(req: MatchStepsRequest) -> MatchStepsResponse:
        threshold = req.min_similarity if req.min_similarity is not None else _default_threshold()
        fw_key = tuple(sorted(set(req.frameworks))) if req.frameworks is not None else None
        embedding_model = req.embedding_model or _default_embedding_model()
        def infer():
            matcher = _get_matcher(fw_key, embedding_model)
            raw = matcher.match_steps(req.steps, top_k=req.top_k, min_similarity=threshold)
            return MatchStepsResponse(results=raw)
        return await _infer(infer)

    return app


app = create_app(warm=False)
