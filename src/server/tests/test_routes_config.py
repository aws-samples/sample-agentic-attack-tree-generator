"""Unit tests for the config API endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from server.app import app
from server.models import ConfigResponse
from server.routes.config import get_config, set_config


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset the module-level config override before each test."""
    set_config(None)
    yield
    set_config(None)


@pytest.fixture()
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# GET /api/config endpoint tests
# ---------------------------------------------------------------------------


class TestConfigEndpoint:
    def test_returns_200(self, client: TestClient) -> None:
        # Use set_config so we don't depend on the workspace config file
        set_config(ConfigResponse(
            model_provider="AWS Bedrock",
            model_id="test-model",
            embeddings_model="test-embed",
            default_browse_path="/tmp",
        ))
        resp = client.get("/api/config")
        assert resp.status_code == 200

    def test_response_shape(self, client: TestClient) -> None:
        set_config(ConfigResponse(
            model_provider="AWS Bedrock",
            model_id="some-model",
            embeddings_model="some-embed",
            default_browse_path="/tmp",
        ))
        resp = client.get("/api/config")
        data = resp.json()
        assert "model_provider" in data
        assert "model_id" in data
        assert "embeddings_model" in data
        assert "default_browse_path" in data

    def test_returns_set_config_values(self, client: TestClient) -> None:
        set_config(ConfigResponse(
            model_provider="Anthropic",
            model_id="claude-4",
            embeddings_model="custom-embed",
            default_browse_path="/workspace",
        ))
        resp = client.get("/api/config")
        data = resp.json()
        assert data["model_provider"] == "Anthropic"
        assert data["model_id"] == "claude-4"
        assert data["embeddings_model"] == "custom-embed"
        assert data["default_browse_path"] == "/workspace"


# ---------------------------------------------------------------------------
# get_config / set_config logic tests
# ---------------------------------------------------------------------------


class TestGetSetConfig:
    def test_set_config_overrides(self) -> None:
        override = ConfigResponse(
            model_provider="Test",
            model_id="test-id",
            embeddings_model="test-embed",
            default_browse_path="/test",
        )
        set_config(override)
        assert get_config() == override

    def test_set_config_none_resets(self) -> None:
        set_config(ConfigResponse(
            model_provider="X",
            model_id="Y",
            embeddings_model="Z",
            default_browse_path="/tmp",
        ))
        set_config(None)
        # Should fall through to file or defaults — just verify it doesn't crash
        result = get_config()
        assert isinstance(result, ConfigResponse)


# ---------------------------------------------------------------------------
# YAML config loading tests
# ---------------------------------------------------------------------------


class TestYamlConfigLoading:
    def test_loads_from_yaml(self, tmp_path: Path, monkeypatch) -> None:
        config_dir = tmp_path / ".threatforest"
        config_dir.mkdir()
        config_file = config_dir / "config.yaml"
        config_file.write_text(yaml.dump({
            "bedrock": {"model_id": "my-custom-model"},
            "embeddings": {"model": "my-embed-model"},
        }))
        monkeypatch.chdir(tmp_path)
        set_config(None)

        result = get_config()
        assert result.model_provider == "AWS Bedrock"
        assert result.model_id == "my-custom-model"
        assert result.embeddings_model == "my-embed-model"
        assert result.default_browse_path == str(tmp_path)

    def test_defaults_when_no_yaml(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        set_config(None)

        result = get_config()
        assert result.model_provider == "AWS Bedrock"
        assert result.model_id == "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
        assert result.embeddings_model == "basel/ATTACK-BERT"
        assert result.default_browse_path == str(tmp_path)

    def test_partial_yaml_uses_defaults(self, tmp_path: Path, monkeypatch) -> None:
        config_dir = tmp_path / ".threatforest"
        config_dir.mkdir()
        config_file = config_dir / "config.yaml"
        # Only embeddings, no bedrock section
        config_file.write_text(yaml.dump({
            "embeddings": {"model": "custom-bert"},
        }))
        monkeypatch.chdir(tmp_path)
        set_config(None)

        result = get_config()
        # No bedrock key → falls back to default provider and model_id
        assert result.model_provider == "AWS Bedrock"
        assert result.model_id == "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
        assert result.embeddings_model == "custom-bert"
        assert result.default_browse_path == str(tmp_path)

    def test_empty_yaml_uses_defaults(self, tmp_path: Path, monkeypatch) -> None:
        config_dir = tmp_path / ".threatforest"
        config_dir.mkdir()
        (config_dir / "config.yaml").write_text("")
        monkeypatch.chdir(tmp_path)
        set_config(None)

        result = get_config()
        assert result.model_provider == "AWS Bedrock"
        assert result.model_id == "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
        assert result.embeddings_model == "basel/ATTACK-BERT"
        assert result.default_browse_path == str(tmp_path)


# ---------------------------------------------------------------------------
# GET /api/config/providers endpoint tests
# ---------------------------------------------------------------------------


class TestProvidersEndpoint:
    def test_returns_200(self, client: TestClient) -> None:
        resp = client.get("/api/config/providers")
        assert resp.status_code == 200

    def test_returns_provider_list(self, client: TestClient) -> None:
        resp = client.get("/api/config/providers")
        data = resp.json()
        assert "providers" in data
        assert isinstance(data["providers"], list)
        assert len(data["providers"]) == 5
        assert "AWS Bedrock" in data["providers"]
        assert "Anthropic" in data["providers"]
        assert "OpenAI" in data["providers"]
        assert "Google Gemini" in data["providers"]
        assert "Ollama" in data["providers"]


# ---------------------------------------------------------------------------
# POST /api/config/test endpoint tests
# ---------------------------------------------------------------------------


class TestConfigTestEndpoint:
    def test_ollama_returns_success_without_credentials(self, client: TestClient) -> None:
        """Ollama doesn't need credentials — should always succeed."""
        resp = client.post("/api/config/test", json={
            "provider": "Ollama",
            "model_id": "llama3",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "no credentials" in data["message"].lower()

    def test_aws_bedrock_calls_real_validator(self, client: TestClient) -> None:
        """AWS Bedrock test should attempt a real STS call (may succeed or fail
        depending on environment, but should not crash)."""
        resp = client.post("/api/config/test", json={
            "provider": "AWS Bedrock",
            "model_id": "anthropic.claude-sonnet-4-5-20250929-v1:0",
            "aws_profile": "nonexistent-profile-for-test",
        })
        assert resp.status_code == 200
        data = resp.json()
        # Should return a result (success or failure) — not crash
        assert "success" in data
        assert "message" in data
        assert isinstance(data["message"], str)
        assert len(data["message"]) > 0

    def test_api_key_provider_without_key_returns_failure(self, client: TestClient) -> None:
        """API-key providers without a key should fail."""
        resp = client.post("/api/config/test", json={
            "provider": "Anthropic",
            "model_id": "claude-4",
        })
        data = resp.json()
        assert data["success"] is False
        assert "API key" in data["message"]

    def test_api_key_provider_with_key_returns_success(self, client: TestClient) -> None:
        """API-key providers with a key should succeed (key validated on first use)."""
        resp = client.post("/api/config/test", json={
            "provider": "Anthropic",
            "model_id": "claude-4",
            "api_key": "sk-ant-test-key",
        })
        data = resp.json()
        assert data["success"] is True

    def test_empty_provider_returns_failure(self, client: TestClient) -> None:
        resp = client.post("/api/config/test", json={
            "provider": "",
            "model_id": "some-model",
        })
        data = resp.json()
        assert data["success"] is False
        assert "Provider" in data["message"]

    def test_empty_model_id_returns_failure(self, client: TestClient) -> None:
        resp = client.post("/api/config/test", json={
            "provider": "AWS Bedrock",
            "model_id": "",
        })
        data = resp.json()
        assert data["success"] is False
        assert "Model ID" in data["message"]

    def test_unknown_provider_returns_failure(self, client: TestClient) -> None:
        resp = client.post("/api/config/test", json={
            "provider": "UnknownProvider",
            "model_id": "some-model",
        })
        data = resp.json()
        assert data["success"] is False
        assert "Unknown provider" in data["message"]

    def test_with_aws_profile(self, client: TestClient) -> None:
        """AWS Bedrock with a profile should attempt real validation (may fail
        if profile doesn't exist, but should not crash)."""
        resp = client.post("/api/config/test", json={
            "provider": "AWS Bedrock",
            "model_id": "some-model",
            "aws_profile": "my-profile",
        })
        data = resp.json()
        # Should return a structured response regardless of whether creds are valid
        assert "success" in data
        assert "message" in data


# ---------------------------------------------------------------------------
# POST /api/config/save endpoint tests
# ---------------------------------------------------------------------------


class TestConfigSaveEndpoint:
    def test_save_creates_config_file(self, tmp_path: Path, monkeypatch, client: TestClient) -> None:
        monkeypatch.chdir(tmp_path)
        set_config(None)

        resp = client.post("/api/config/save", json={
            "provider": "AWS Bedrock",
            "model_id": "my-model-id",
            "aws_profile": "dev-profile",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

        # Verify the file was written
        config_path = tmp_path / ".threatforest" / "config.yaml"
        assert config_path.is_file()
        content = yaml.safe_load(config_path.read_text())
        assert content["bedrock"]["model_id"] == "my-model-id"
        assert content["bedrock"]["aws_profile"] == "dev-profile"

    def test_save_anthropic_provider(self, tmp_path: Path, monkeypatch, client: TestClient) -> None:
        monkeypatch.chdir(tmp_path)
        set_config(None)

        resp = client.post("/api/config/save", json={
            "provider": "Anthropic",
            "model_id": "claude-4",
        })
        assert resp.status_code == 200

        config_path = tmp_path / ".threatforest" / "config.yaml"
        content = yaml.safe_load(config_path.read_text())
        assert "anthropic" in content
        assert content["anthropic"]["model_id"] == "claude-4"
        # bedrock key should not be present
        assert "bedrock" not in content

    def test_save_unknown_provider_returns_400(self, client: TestClient) -> None:
        resp = client.post("/api/config/save", json={
            "provider": "UnknownProvider",
            "model_id": "some-model",
        })
        assert resp.status_code == 400

    def test_save_empty_provider_returns_400(self, client: TestClient) -> None:
        resp = client.post("/api/config/save", json={
            "provider": "",
            "model_id": "some-model",
        })
        assert resp.status_code == 400

    def test_save_empty_model_id_returns_400(self, client: TestClient) -> None:
        resp = client.post("/api/config/save", json={
            "provider": "AWS Bedrock",
            "model_id": "",
        })
        assert resp.status_code == 400

    def test_save_preserves_embeddings(self, tmp_path: Path, monkeypatch, client: TestClient) -> None:
        """Saving a new provider config should preserve existing embeddings section."""
        monkeypatch.chdir(tmp_path)
        set_config(None)

        # Create initial config with embeddings
        config_dir = tmp_path / ".threatforest"
        config_dir.mkdir()
        (config_dir / "config.yaml").write_text(yaml.dump({
            "bedrock": {"model_id": "old-model"},
            "embeddings": {"model": "my-bert"},
        }))

        resp = client.post("/api/config/save", json={
            "provider": "Anthropic",
            "model_id": "claude-new",
        })
        assert resp.status_code == 200

        content = yaml.safe_load((config_dir / "config.yaml").read_text())
        assert "anthropic" in content
        assert content["anthropic"]["model_id"] == "claude-new"
        assert "bedrock" not in content  # old provider removed
        assert content["embeddings"]["model"] == "my-bert"  # preserved

    def test_save_round_trip(self, tmp_path: Path, monkeypatch, client: TestClient) -> None:
        """Save config then read it back — values should match."""
        monkeypatch.chdir(tmp_path)
        set_config(None)

        client.post("/api/config/save", json={
            "provider": "AWS Bedrock",
            "model_id": "round-trip-model",
            "aws_profile": "rt-profile",
        })

        resp = client.get("/api/config")
        data = resp.json()
        assert data["model_provider"] == "AWS Bedrock"
        assert data["model_id"] == "round-trip-model"
        assert data["aws_profile"] == "rt-profile"


# ---------------------------------------------------------------------------
# aws_profile in ConfigResponse tests
# ---------------------------------------------------------------------------


class TestAwsProfileInConfig:
    def test_aws_profile_from_yaml(self, tmp_path: Path, monkeypatch) -> None:
        config_dir = tmp_path / ".threatforest"
        config_dir.mkdir()
        (config_dir / "config.yaml").write_text(yaml.dump({
            "bedrock": {"model_id": "test-model", "aws_profile": "my-profile"},
        }))
        monkeypatch.chdir(tmp_path)
        set_config(None)

        result = get_config()
        assert result.aws_profile == "my-profile"

    def test_aws_profile_none_when_missing(self, tmp_path: Path, monkeypatch) -> None:
        config_dir = tmp_path / ".threatforest"
        config_dir.mkdir()
        (config_dir / "config.yaml").write_text(yaml.dump({
            "bedrock": {"model_id": "test-model"},
        }))
        monkeypatch.chdir(tmp_path)
        set_config(None)

        result = get_config()
        assert result.aws_profile is None

    def test_aws_profile_in_api_response(self, client: TestClient) -> None:
        set_config(ConfigResponse(
            model_provider="AWS Bedrock",
            model_id="test",
            embeddings_model="test",
            default_browse_path="/tmp",
            aws_profile="test-profile",
        ))
        resp = client.get("/api/config")
        data = resp.json()
        assert data["aws_profile"] == "test-profile"

    def test_aws_profile_null_in_api_response(self, client: TestClient) -> None:
        set_config(ConfigResponse(
            model_provider="AWS Bedrock",
            model_id="test",
            embeddings_model="test",
            default_browse_path="/tmp",
        ))
        resp = client.get("/api/config")
        data = resp.json()
        assert data["aws_profile"] is None
