import asyncio
import threading
from importlib import import_module
from types import SimpleNamespace

import pytest
from threatforest.modules.workflow.ttc_mappings.matcher import TTCMatcher


def test_batch_encoding_preserves_order_and_explicit_no_match():
    calls = []
    technique = SimpleNamespace(primary_technique_id="T1190", name="Exploit application",
                                description="Exploit a public application", tactics=["initial-access"])

    class Embeddings:
        def get_batch_embeddings(self, texts, show_progress=False):
            calls.append(list(texts))
            return [[1.0, 0.0], [0.0, 1.0]]

    class Search:
        def search_batch(self, vectors, top_k, min_similarity):
            calls.append((vectors, top_k, min_similarity))
            return [[{"technique": technique, "similarity": .8}], []]

    matcher = TTCMatcher()
    matcher._initialized = True
    matcher._embedding_service = Embeddings()
    matcher._graphs = {"attack": []}
    matcher._searches = {"attack": Search()}
    result = matcher.match_steps(["exploit public application", "benign change"], min_similarity=.6)
    assert [row["attack_step"] for row in result] == ["exploit public application", "benign change"]
    assert result[0]["matches"][0]["technique_id"] == "T1190"
    assert result[1]["matches"] == []
    assert len(calls) == 2
    assert calls[1][2] == .6
    assert matcher.min_similarity == .3


def test_failed_embeddings_are_not_abstentions():
    matcher = TTCMatcher()
    matcher._initialized = True
    matcher._embedding_service = SimpleNamespace(get_batch_embeddings=lambda *a, **k: [[]])
    with pytest.raises(RuntimeError, match="Embedding inference failed"):
        matcher.match_steps(["attack"])


def test_health_remains_responsive_during_inference(monkeypatch):
    module = import_module("ml_service.app")
    started, release = threading.Event(), threading.Event()

    def work():
        started.set()
        release.wait(5)
        return "done"

    async def exercise():
        task = asyncio.create_task(module._infer(work))
        while not started.is_set():
            await asyncio.sleep(.001)
        app = module.create_app()
        health = next(route.endpoint for route in app.routes if getattr(route, "name", None) == "health")
        assert (await asyncio.wait_for(health(), .1))["status"] == "ok"
        release.set()
        assert await task == "done"

    try:
        asyncio.run(exercise())
    finally:
        release.set()
