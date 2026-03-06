"""Tests for graph assembly — wiring, conditional edges, node registration."""

import asyncio
import json
from unittest.mock import patch

import pytest

from strands import Agent
from strands.handlers import null_callback_handler

from threatforest.agents.scanner.agent import STATE_DIR


def _make_stub_agent():
    """Create a minimal real Agent that won't call any LLM."""
    # Use a mock model that just returns immediately
    from unittest.mock import MagicMock
    model = MagicMock()
    return Agent(model=model, system_prompt="stub", callback_handler=null_callback_handler())


def _patch_all_agent_factories():
    """Patch all agent factories to return stub agents."""
    stub = _make_stub_agent
    return [
        patch("threatforest.agents.scanner.agent.create_scanner_agent", side_effect=lambda rp: stub()),
        patch("threatforest.agents.threat.agent.create_threat_agent", side_effect=lambda rp: stub()),
    ]


class TestGraphWiring:
    def _build(self, tmp_path):
        (tmp_path / STATE_DIR).mkdir(parents=True)
        patches = _patch_all_agent_factories()
        for p in patches:
            p.start()
        try:
            from threatforest.agents.graph import build_graph
            return build_graph(str(tmp_path))
        finally:
            for p in patches:
                p.stop()

    def test_all_nodes_registered(self, tmp_path):
        graph = self._build(tmp_path)
        expected = {
            "scanner", "scanner_verifier",
            "threat", "threat_verifier",
            "parallel_pipeline", "parallel_verifier",
            "report", "report_verifier",
        }
        assert set(graph.nodes.keys()) == expected

    def test_entry_point_is_scanner(self, tmp_path):
        graph = self._build(tmp_path)
        entry_ids = {n.node_id for n in graph.entry_points}
        assert entry_ids == {"scanner"}

    def test_max_node_executions(self, tmp_path):
        graph = self._build(tmp_path)
        assert graph.max_node_executions == 50

    def test_has_edges(self, tmp_path):
        graph = self._build(tmp_path)
        assert len(graph.edges) > 0


class TestConditionalEdges:
    def test_is_aws_true(self, tmp_path):
        state_dir = tmp_path / STATE_DIR
        state_dir.mkdir(parents=True)
        (state_dir / "scanner_context.json").write_text(json.dumps({"cloud_provider": "aws"}))
        from threatforest.agents.graph import _is_aws_project
        assert _is_aws_project(str(tmp_path)) is True

    def test_is_aws_false_gcp(self, tmp_path):
        state_dir = tmp_path / STATE_DIR
        state_dir.mkdir(parents=True)
        (state_dir / "scanner_context.json").write_text(json.dumps({"cloud_provider": "gcp"}))
        from threatforest.agents.graph import _is_aws_project
        assert _is_aws_project(str(tmp_path)) is False

    def test_is_aws_missing_file(self, tmp_path):
        from threatforest.agents.graph import _is_aws_project
        assert _is_aws_project(str(tmp_path)) is False


class TestFunctionAgent:
    def test_function_agent_invokes(self):
        from threatforest.agents.graph import FunctionAgent

        called = []
        def my_fn(repo_path):
            called.append(repo_path)
            return "ok"

        agent = FunctionAgent(my_fn, "/tmp/test", "test_node")
        result = asyncio.run(agent.invoke_async("do it"))

        assert len(called) == 1
        assert called[0] == "/tmp/test"
        assert result.status.value == "completed"
