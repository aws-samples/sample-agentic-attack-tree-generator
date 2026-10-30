"""Fast unit coverage for per-request embedding-model routing."""

import asyncio
from importlib import import_module

app_module = import_module("ml_service.app")


def test_match_steps_routes_embedding_model_without_global_mutation(monkeypatch) -> None:
    calls = []

    class Matcher:
        def match_steps(self, steps, top_k, min_similarity):
            calls.append(min_similarity)
            return []

    def fake_get_matcher(frameworks, embedding_model):
        calls.append((frameworks, embedding_model))
        return Matcher()

    monkeypatch.setattr(app_module, "_get_matcher", fake_get_matcher)
    app = app_module.create_app(warm=False)
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "name", None) == "match_steps"
    )

    first = asyncio.run(
        endpoint(
            app_module.MatchStepsRequest(
                steps=["one"],
                top_k=3,
                min_similarity=0.4,
                frameworks=["attack"],
                embedding_model="embedding-a",
            )
        )
    )
    second = asyncio.run(
        endpoint(
            app_module.MatchStepsRequest(
                steps=["two"],
                top_k=5,
                min_similarity=0.6,
                frameworks=["atlas"],
                embedding_model="embedding-b",
            )
        )
    )

    assert first.results == []
    assert second.results == []
    assert calls == [
        (("attack",), "embedding-a"), 0.4,
        (("atlas",), "embedding-b"), 0.6,
    ]
