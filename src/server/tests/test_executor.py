"""Unit tests for the orchestrator executor."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from server.executor import (
    _extract_model_settings,
    _load_config_yaml,
    create_orchestrator_executor,
)
from server.models import RunConfig
from server.run_manager import ProgressEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(workspace: Path, content: dict[str, Any]) -> Path:
    """Write a .threatforest/config.yaml inside *workspace*."""
    config_dir = workspace / ".threatforest"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.yaml"
    config_path.write_text(yaml.dump(content), encoding="utf-8")
    return config_path


def _make_config(project_path: str) -> RunConfig:
    return RunConfig(project_path=project_path, threat_source="auto")


# ---------------------------------------------------------------------------
# _load_config_yaml
# ---------------------------------------------------------------------------


class TestLoadConfigYaml:
    def test_raises_when_missing(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="configuration not found"):
            _load_config_yaml(tmp_path)

    def test_returns_parsed_yaml(self, tmp_path: Path) -> None:
        _write_config(tmp_path, {"bedrock": {"model_id": "my-model"}})
        result = _load_config_yaml(tmp_path)
        assert result["bedrock"]["model_id"] == "my-model"

    def test_returns_empty_dict_for_empty_file(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".threatforest"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yaml").write_text("", encoding="utf-8")
        result = _load_config_yaml(tmp_path)
        assert result == {}


# ---------------------------------------------------------------------------
# _extract_model_settings
# ---------------------------------------------------------------------------


class TestExtractModelSettings:
    def test_extracts_bedrock_settings(self) -> None:
        raw = {"bedrock": {"model_id": "claude-v2", "aws_profile": "dev"}}
        model, profile = _extract_model_settings(raw)
        assert model == "claude-v2"
        assert profile == "dev"

    def test_extracts_anthropic_settings(self) -> None:
        raw = {"anthropic": {"model_id": "claude-3"}}
        model, profile = _extract_model_settings(raw)
        assert model == "claude-3"
        assert profile is None

    def test_raises_when_no_model_id(self) -> None:
        raw = {"bedrock": {"aws_profile": "dev"}}
        with pytest.raises(RuntimeError, match="No model_id configured"):
            _extract_model_settings(raw)

    def test_raises_for_empty_config(self) -> None:
        with pytest.raises(RuntimeError, match="No model_id configured"):
            _extract_model_settings({})

    def test_skips_non_dict_sections(self) -> None:
        raw = {"bedrock": "not-a-dict", "anthropic": {"model_id": "ok"}}
        model, profile = _extract_model_settings(raw)
        assert model == "ok"


# ---------------------------------------------------------------------------
# create_orchestrator_executor — config validation
# ---------------------------------------------------------------------------


class TestExecutorConfigValidation:
    """Tests that the executor raises on missing/bad config.

    These tests do NOT require the real ThreatForest engine because
    they fail before the import is reached.
    """

    def test_raises_when_config_yaml_missing(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        executor = create_orchestrator_executor(tmp_path)
        events: list[ProgressEvent] = []
        with pytest.raises(RuntimeError, match="configuration not found"):
            executor(_make_config(str(project)), events.append)

    def test_raises_when_model_id_missing(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        _write_config(tmp_path, {"bedrock": {"aws_profile": "dev"}})
        executor = create_orchestrator_executor(tmp_path)
        events: list[ProgressEvent] = []
        with pytest.raises(RuntimeError, match="No model_id configured"):
            executor(_make_config(str(project)), events.append)

    def test_raises_when_config_yaml_empty(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        _write_config(tmp_path, {})
        executor = create_orchestrator_executor(tmp_path)
        events: list[ProgressEvent] = []
        with pytest.raises(RuntimeError, match="No model_id configured"):
            executor(_make_config(str(project)), events.append)
