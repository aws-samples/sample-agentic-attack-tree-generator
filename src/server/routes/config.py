"""Configuration API route."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter

from fastapi import HTTPException

from server.models import (
    ConfigResponse,
    ConfigSaveRequest,
    ConfigTestRequest,
    ConfigTestResponse,
    LangfuseConfigResponse,
    LangfuseConfigSaveRequest,
    ProvidersResponse,
)

router = APIRouter()

# Available model providers
AVAILABLE_PROVIDERS = [
    "AWS Bedrock",
    "Anthropic",
    "OpenAI",
    "Google Gemini",
    "Ollama",
]

# Mapping from provider display name to YAML config key
_PROVIDER_TO_KEY: dict[str, str] = {
    "AWS Bedrock": "bedrock",
    "Anthropic": "anthropic",
    "OpenAI": "openai",
    "Google Gemini": "google_gemini",
    "Ollama": "ollama",
}

# Reverse mapping: YAML key → provider display name
_KEY_TO_PROVIDER: dict[str, str] = {v: k for k, v in _PROVIDER_TO_KEY.items()}

# Defaults when config file is missing or incomplete
_DEFAULT_CONFIG = ConfigResponse(
    model_provider="AWS Bedrock",
    model_id="global.anthropic.claude-sonnet-4-5-20250929-v1:0",
    embeddings_model="basel/ATTACK-BERT",
    default_browse_path=str(Path.cwd()),
)

# Module-level config — overridable via set_config() for testing
_config: ConfigResponse | None = None

# Root directory of the repo (src/server/routes/config.py → src/server/routes → src/server → src → repo)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _resolve_config_path() -> Path:
    """Find config.yaml using the same resolution order as the pipeline Config class.

    Priority:
    1. ``.threatforest/config.yaml`` in the current working directory
    2. ``<repo_root>/.threatforest/config.yaml`` (where the CLI writes by default)

    Returns the first existing path, or the ROOT_DIR path if neither exists
    (so save_config creates the file in the canonical CLI location).
    """
    cwd_config = Path(".threatforest") / "config.yaml"
    if cwd_config.is_file():
        return cwd_config
    root_config = _REPO_ROOT / ".threatforest" / "config.yaml"
    return root_config


def _load_config_from_yaml(path: Path) -> ConfigResponse:
    """Parse a .threatforest/config.yaml file into a ConfigResponse."""
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    embeddings: dict[str, Any] = raw.get("embeddings", {})
    embeddings_model = embeddings.get("model", _DEFAULT_CONFIG.embeddings_model)

    # Detect provider from top-level keys in the YAML
    model_provider = _DEFAULT_CONFIG.model_provider
    model_id = _DEFAULT_CONFIG.model_id
    aws_profile: str | None = None

    for yaml_key, provider_name in _KEY_TO_PROVIDER.items():
        if yaml_key in raw:
            section = raw[yaml_key] if isinstance(raw[yaml_key], dict) else {}
            model_provider = provider_name
            model_id = section.get("model_id", _DEFAULT_CONFIG.model_id)
            aws_profile = section.get("aws_profile")
            break

    return ConfigResponse(
        model_provider=model_provider,
        model_id=model_id,
        embeddings_model=embeddings_model,
        default_browse_path=str(Path.cwd()),
        aws_profile=aws_profile,
    )


def get_config() -> ConfigResponse:
    """Return the current configuration.

    Resolution order:
    1. Explicitly set config (via ``set_config``)
    2. ``.threatforest/config.yaml`` — CWD first, then repo root (matches CLI)
    3. Hard-coded defaults
    """
    if _config is not None:
        return _config

    config_path = _resolve_config_path()
    if config_path.is_file():
        return _load_config_from_yaml(config_path)

    # Return defaults with current working directory resolved at call time
    return ConfigResponse(
        model_provider=_DEFAULT_CONFIG.model_provider,
        model_id=_DEFAULT_CONFIG.model_id,
        embeddings_model=_DEFAULT_CONFIG.embeddings_model,
        default_browse_path=str(Path.cwd()),
    )


def set_config(config: ConfigResponse | None) -> None:
    """Override the module-level config (useful for testing).

    Pass ``None`` to reset to auto-detection.
    """
    global _config
    _config = config


@router.get("/config", response_model=ConfigResponse)
async def read_config() -> ConfigResponse:
    """Return the current ThreatForest model/provider configuration."""
    return get_config()


@router.get("/config/frameworks")
async def list_frameworks() -> dict:
    """Return available threat mapping frameworks from config."""
    import yaml
    config_path = _resolve_config_path()
    frameworks = {
        "attack": {
            "name": "MITRE ATT&CK Enterprise",
            "description": "835 techniques — cloud, network, endpoint",
        },
        "atlas": {
            "name": "MITRE ATLAS",
            "description": "AI/ML adversarial threats",
        },
    }
    if config_path.is_file():
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        fw = raw.get("frameworks", {})
        if fw:
            frameworks = {
                k: {"name": v.get("name", k), "description": v.get("description", "")}
                for k, v in fw.items()
            }
    return {"frameworks": frameworks}


@router.get("/config/providers", response_model=ProvidersResponse)
async def list_providers() -> ProvidersResponse:
    """Return the list of available model providers."""
    return ProvidersResponse(providers=AVAILABLE_PROVIDERS)


@router.post("/config/test", response_model=ConfigTestResponse)
async def test_config(request: ConfigTestRequest) -> ConfigTestResponse:
    """Validate a model provider configuration by making a real API call.

    For AWS Bedrock: uses STS get_caller_identity to validate credentials.
    For other providers: validates that required fields are present.
    """
    if not request.provider or not request.provider.strip():
        return ConfigTestResponse(success=False, message="Provider is required.")
    if not request.model_id or not request.model_id.strip():
        return ConfigTestResponse(success=False, message="Model ID is required.")
    if request.provider not in AVAILABLE_PROVIDERS:
        return ConfigTestResponse(
            success=False,
            message=f"Unknown provider '{request.provider}'. "
            f"Available: {', '.join(AVAILABLE_PROVIDERS)}",
        )

    # For AWS Bedrock — do a real credential check via STS
    if request.provider == "AWS Bedrock":
        return _test_aws_connection(
            profile=request.aws_profile,
            region=request.aws_region,
        )

    # For Ollama — no credentials needed, just confirm
    if request.provider == "Ollama":
        return ConfigTestResponse(
            success=True,
            message="Ollama runs locally — no credentials required.",
        )

    # For API-key providers — validate the key looks reasonable
    if request.api_key:
        return ConfigTestResponse(
            success=True,
            message=f"API key configured for {request.provider}. "
            f"Key will be validated on first use.",
        )

    return ConfigTestResponse(
        success=False,
        message=f"{request.provider} requires an API key. Please provide one.",
    )


def _test_aws_connection(
    profile: str | None = None,
    region: str | None = None,
) -> ConfigTestResponse:
    """Test AWS credentials using STS get_caller_identity.

    Uses the same validation approach as the CLI's AWSValidator.
    """
    import sys
    from pathlib import Path as _Path

    # Add ThreatForest src to path so we can import the validator
    # src/server/routes/config.py → routes/ → server/ → src/ → repo root
    repo_root = _Path(__file__).resolve().parent.parent.parent.parent
    tf_src = str(repo_root / "src")
    if tf_src not in sys.path:
        sys.path.insert(0, tf_src)

    try:
        from threatforest.modules.utils.aws_validator import (  # type: ignore[import-untyped]
            test_aws_connection,
        )

        result = test_aws_connection(
            profile=profile or None,
            region=region or "us-east-1",
            show_output=False,
        )

        if result["success"]:
            arn = result.get("arn", "")
            identity = arn.split("/")[-1] if "/" in arn else arn
            account = result.get("account_id", "")
            return ConfigTestResponse(
                success=True,
                message=f"✓ AWS connection successful! "
                f"Account: {account}, Identity: {identity}, "
                f"Region: {result.get('region', 'us-east-1')}",
            )
        else:
            error = result.get("error", "Unknown error")
            suggestions = result.get("suggestions", [])
            hint = f" Suggestion: {suggestions[0]}" if suggestions else ""
            return ConfigTestResponse(
                success=False,
                message=f"AWS connection failed: {error}.{hint}",
            )

    except ImportError:
        # Fallback if boto3 or the validator isn't available
        return ConfigTestResponse(
            success=False,
            message="Cannot test AWS connection — boto3 is not installed. "
            "Install it with: pip install boto3",
        )
    except Exception as exc:
        return ConfigTestResponse(
            success=False,
            message=f"Connection test error: {exc}",
        )


@router.post("/config/save", response_model=ConfigTestResponse)
async def save_config(request: ConfigSaveRequest) -> ConfigTestResponse:
    """Save model provider configuration to .threatforest/config.yaml."""
    if not request.provider or not request.provider.strip():
        raise HTTPException(status_code=400, detail="Provider is required.")
    if not request.model_id or not request.model_id.strip():
        raise HTTPException(status_code=400, detail="Model ID is required.")

    yaml_key = _PROVIDER_TO_KEY.get(request.provider)
    if yaml_key is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider '{request.provider}'. "
            f"Available: {', '.join(AVAILABLE_PROVIDERS)}",
        )

    config_path = _resolve_config_path()
    config_dir = config_path.parent

    # Build the provider section
    provider_section: dict[str, Any] = {"model_id": request.model_id}
    if request.aws_profile:
        provider_section["aws_profile"] = request.aws_profile

    # Load existing config to preserve non-provider sections (e.g. embeddings)
    existing: dict[str, Any] = {}
    if config_path.is_file():
        existing = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    # Remove all provider keys, then set the new one
    for key in _PROVIDER_TO_KEY.values():
        existing.pop(key, None)
    existing[yaml_key] = provider_section

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            yaml.dump(existing, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write config: {exc}") from exc

    # Reset the route-level cache so next GET /config reflects the new file
    set_config(None)

    # Reset the pipeline Config singleton so the next run reloads from disk
    try:
        import sys
        from pathlib import Path as _Path

        repo_root = _Path(__file__).resolve().parent.parent.parent.parent
        tf_src = str(repo_root / "src")
        if tf_src not in sys.path:
            sys.path.insert(0, tf_src)

        from threatforest.config import config as tf_config  # type: ignore[import-untyped]
        tf_config.reset()
    except Exception:
        pass  # Non-fatal: pipeline will pick up the file on restart if reset fails

    return ConfigTestResponse(success=True, message="Configuration saved successfully.")


# ---------------------------------------------------------------------------
# Langfuse configuration
# ---------------------------------------------------------------------------

def _get_env_manager():
    """Lazily import and return an EnvManager instance."""
    import sys
    from pathlib import Path as _Path

    repo_root = _Path(__file__).resolve().parent.parent.parent.parent
    tf_src = str(repo_root / "src")
    if tf_src not in sys.path:
        sys.path.insert(0, tf_src)

    from threatforest.modules.utils.env_manager import EnvManager  # type: ignore[import-untyped]
    return EnvManager()


@router.get("/config/langfuse", response_model=LangfuseConfigResponse)
async def read_langfuse_config() -> LangfuseConfigResponse:
    """Return the current Langfuse tracing configuration."""
    env = _get_env_manager()
    return LangfuseConfigResponse(
        enabled=env.get_value("LANGFUSE_ENABLED") == "true",
        public_key=env.get_value("LANGFUSE_PUBLIC_KEY"),
        secret_key_configured=bool(env.get_value("LANGFUSE_SECRET_KEY")),
        host=env.get_value("LANGFUSE_HOST") or "https://cloud.langfuse.com",
    )


@router.post("/config/langfuse/test", response_model=ConfigTestResponse)
async def test_langfuse_config(request: LangfuseConfigSaveRequest) -> ConfigTestResponse:
    """Test Langfuse connection using the provided or stored credentials."""
    env = _get_env_manager()
    public_key = request.public_key or env.get_value("LANGFUSE_PUBLIC_KEY")
    secret_key = request.secret_key or env.get_value("LANGFUSE_SECRET_KEY")
    host = request.host or env.get_value("LANGFUSE_HOST") or "https://cloud.langfuse.com"

    if not public_key or not secret_key:
        return ConfigTestResponse(
            success=False,
            message="Public key and secret key are required to test the connection.",
        )

    try:
        from langfuse import Langfuse  # type: ignore[import-untyped]

        client = Langfuse(public_key=public_key, secret_key=secret_key, host=host)
        client.auth_check()
        client.flush()
        return ConfigTestResponse(success=True, message="Langfuse connection successful.")
    except ImportError:
        return ConfigTestResponse(
            success=False,
            message="langfuse package is not installed. Install it with: pip install langfuse",
        )
    except Exception as exc:
        return ConfigTestResponse(success=False, message=f"Langfuse connection failed: {exc}")


@router.post("/config/langfuse", response_model=ConfigTestResponse)
async def save_langfuse_config(request: LangfuseConfigSaveRequest) -> ConfigTestResponse:
    """Save Langfuse tracing configuration."""
    if request.enabled and (not request.public_key or not request.secret_key):
        raise HTTPException(
            status_code=400,
            detail="Public key and secret key are required when enabling Langfuse.",
        )

    env = _get_env_manager()
    env.set_value("LANGFUSE_ENABLED", "true" if request.enabled else "false")
    if request.public_key:
        env.set_value("LANGFUSE_PUBLIC_KEY", request.public_key)
    if request.secret_key:
        env.set_value("LANGFUSE_SECRET_KEY", request.secret_key)
    env.set_value("LANGFUSE_HOST", request.host)

    return ConfigTestResponse(success=True, message="Langfuse configuration saved.")
