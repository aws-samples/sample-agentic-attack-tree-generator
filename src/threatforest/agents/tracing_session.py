"""Shared tracing session for a ThreatForest pipeline run.

Provides a session ID and trace_attributes dict that all agents
use so every trace in Langfuse is grouped under the same session.
"""

import uuid

_session_id: str | None = None


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
