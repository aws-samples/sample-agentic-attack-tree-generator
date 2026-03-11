"""Shared tracing session for a ThreatForest pipeline run.

Provides a session ID and trace_attributes dict that all agents
use so every trace in Langfuse is grouped under the same session.
"""

import base64
import os
import uuid

_session_id: str | None = None
_otel_initialized = False


def init_session() -> str:
    """Start a new tracing session and return its ID."""
    global _session_id
    _session_id = f"tf-{uuid.uuid4().hex[:12]}"
    return _session_id


def get_session_id() -> str | None:
    return _session_id


def trace_attrs(agent_name: str) -> dict:
    """Return trace_attributes dict for a Strands Agent."""
    if not _session_id:
        return {}
    return {
        "session.id": _session_id,
        "langfuse.tags": ["threatforest", agent_name],
    }


def setup_langfuse_otel() -> None:
    """Configure Strands OTEL exporter to send traces to Langfuse.

    Reads LANGFUSE_* env vars (already loaded via dotenv) and sets up
    the OpenTelemetry exporter. Safe to call multiple times — the OTEL
    provider is only initialized once.
    """
    global _otel_initialized

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    enabled = os.environ.get("LANGFUSE_ENABLED", "false").lower() == "true"
    host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")

    if not enabled or not public_key or not secret_key:
        return

    auth = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = f"{host}/api/public/otel"
    os.environ["OTEL_EXPORTER_OTLP_HEADERS"] = f"Authorization=Basic {auth}"

    if _otel_initialized:
        return
    _otel_initialized = True

    try:
        from strands.telemetry import StrandsTelemetry
        StrandsTelemetry().setup_otlp_exporter()
    except ImportError:
        pass
