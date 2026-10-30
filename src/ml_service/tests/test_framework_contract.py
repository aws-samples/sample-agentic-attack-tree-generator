"""Focused coverage for the canonical TTP framework contract."""

from __future__ import annotations

import pytest

from threatforest.frameworks import FRAMEWORKS
from threatforest.modules.workflow.ttc_mappings import matcher as matcher_module

DEFAULT_FRAMEWORK_IDS = ("attack", "atlas", "wiz")


class _Graph:
    def __len__(self) -> int:
        return 1


def test_all_default_frameworks_reach_matcher_initialization(monkeypatch, tmp_path) -> None:
    built_frameworks: list[str] = []

    class EmbeddingService:
        def __init__(self, model: str) -> None:
            assert model == "test/embedding-model"

    class GraphBuilder:
        @staticmethod
        def get_or_build(**kwargs):
            built_frameworks.append(kwargs["source_name"])
            return _Graph()

    class VectorSearch:
        def __init__(self, graph: _Graph) -> None:
            assert len(graph) == 1

    from threatforest.config import config

    monkeypatch.setattr(matcher_module, "get_embedding_service", EmbeddingService)
    monkeypatch.setattr(matcher_module, "GraphBuilder", GraphBuilder)
    monkeypatch.setattr(matcher_module, "VectorSearch", VectorSearch)
    monkeypatch.setattr(
        config,
        "graph_file_path_for",
        lambda framework, model: tmp_path / f"{framework}-{model}.json",
    )
    monkeypatch.setattr(
        config,
        "stix_bundle_path_for",
        lambda framework: tmp_path / f"{framework}.json",
    )

    matcher = matcher_module.TTCMatcher(
        frameworks=list(DEFAULT_FRAMEWORK_IDS),
        embedding_model="test/embedding-model",
    )
    matcher._ensure_initialized()

    assert tuple(FRAMEWORKS) == DEFAULT_FRAMEWORK_IDS
    assert tuple(matcher._graphs) == DEFAULT_FRAMEWORK_IDS
    assert built_frameworks == [
        FRAMEWORKS[framework]["source_name"] for framework in DEFAULT_FRAMEWORK_IDS
    ]


def test_unsupported_framework_is_rejected_before_embedding_initialization(
    monkeypatch,
) -> None:
    class EmbeddingService:
        def __init__(self, model: str) -> None:
            raise AssertionError("embedding initialization must not run")

    monkeypatch.setattr(matcher_module, "get_embedding_service", EmbeddingService)
    matcher = matcher_module.TTCMatcher(
        frameworks=["attack", "STRIDE"],
        embedding_model="test/embedding-model",
    )

    with pytest.raises(
        ValueError,
        match=(
            r"Unsupported TTP framework\(s\): STRIDE\. "
            r"Supported frameworks: attack, atlas, wiz"
        ),
    ):
        matcher._ensure_initialized()
