"""Push subgraph input/output as Langfuse SDK traces for annotation queues.

Creates one Langfuse trace per logical subgraph (scanner, threat, and each
per-threat pipeline) with clean input/output JSON so SMEs can review and
score them in Langfuse annotation queues.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_client = None
_session_id: str | None = None
STATE_DIR = ".threatforest/state"


def init(session_id: str) -> bool:
    """Initialize the Langfuse SDK client. Returns True if enabled."""
    global _client, _session_id
    _session_id = session_id

    if os.environ.get("LANGFUSE_ENABLED", "false").lower() != "true":
        return False

    try:
        from langfuse import Langfuse
        _client = Langfuse(
            public_key=os.environ.get("LANGFUSE_PUBLIC_KEY"),
            secret_key=os.environ.get("LANGFUSE_SECRET_KEY"),
            host=os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        )
        return True
    except Exception as e:
        logger.warning("Langfuse SDK init failed: %s", e)
        return False


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def push_subgraph_trace(node_id: str, repo_path: str) -> None:
    """Create a Langfuse trace for a completed subgraph node."""
    if not _client:
        return

    sd = Path(repo_path) / STATE_DIR

    # Map node pairs to a single subgraph trace (only push on verifier completion)
    traces = {
        "scanner_verifier": lambda: _scanner_trace(sd),
        "threat_verifier": lambda: _threat_trace(sd),
        "parallel_verifier": lambda: _parallel_traces(sd),
    }

    builder = traces.get(node_id)
    if not builder:
        return

    try:
        result = builder()
        # builder returns a single tuple or a list of tuples
        items = result if isinstance(result, list) else [result]
        for name, input_data, output_data, tags in items:
            _client.trace(
                name=name,
                session_id=_session_id,
                input=input_data,
                output=output_data,
                tags=["threatforest", "annotation"] + tags,
            )
    except Exception as e:
        logger.warning("Failed to push subgraph trace for %s: %s", node_id, e)


def _scanner_trace(sd: Path):
    output = _read_json(sd / "scanner_context.json")
    return (
        "scanner",
        {"task": "Analyze repository and extract project context"},
        output,
        ["scanner"],
    )


def _threat_trace(sd: Path):
    scanner_ctx = _read_json(sd / "scanner_context.json")
    threats = _read_json(sd / "threats.json")
    return (
        "threat-generation",
        scanner_ctx,
        threats,
        ["threat"],
    )


def _parallel_traces(sd: Path):
    threats = _read_json(sd / "threats.json")
    scanner_ctx = _read_json(sd / "scanner_context.json")
    trees = _read_json(sd / "attack_trees.json")
    mappings = _read_json(sd / "ttp_mappings.json")
    mitigations = _read_json(sd / "mitigations.json")
    return [
        (
            "attack-tree-generation",
            threats,
            trees,
            ["attack-tree"],
        ),
        (
            "ttp-mapping",
            trees,
            mappings,
            ["ttp"],
        ),
        (
            "mitigation-generation",
            {"attack_trees": trees, "ttp_mappings": mappings, "scanner_context": scanner_ctx},
            mitigations,
            ["mitigation"],
        ),
    ]


def flush() -> None:
    """Flush pending Langfuse SDK events."""
    if _client:
        try:
            _client.flush()
        except Exception:
            pass
