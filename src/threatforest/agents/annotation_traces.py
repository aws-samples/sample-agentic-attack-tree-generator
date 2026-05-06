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

from threatforest.workspace import LocalFilesystemWorkspace, Workspace

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


def _read_json(workspace: Workspace, key: str) -> Any:
    if not workspace.exists(key):
        return None
    try:
        return workspace.read_json(key)
    except (json.JSONDecodeError, OSError):
        return None


def _state_workspace(repo_path: str, run_dir: str | None) -> Workspace:
    if run_dir:
        return LocalFilesystemWorkspace(Path(run_dir) / "state")
    return LocalFilesystemWorkspace(Path(repo_path) / STATE_DIR)


def push_subgraph_trace(node_id: str, repo_path: str, run_dir: str | None = None) -> None:
    """Create a Langfuse trace for a completed subgraph node."""
    if not _client:
        return

    ws = _state_workspace(repo_path, run_dir)

    # Map node pairs to a single subgraph trace (only push on verifier completion)
    traces = {
        "scanner_verifier": lambda: _scanner_trace(ws),
        "threat_verifier": lambda: _threat_trace(ws),
        "parallel_verifier": lambda: _parallel_traces(ws),
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


def _scanner_trace(ws: Workspace):
    output = _read_json(ws, "scanner_context.json")
    return (
        "scanner",
        {"task": "Analyze repository and extract project context"},
        output,
        ["scanner"],
    )


def _threat_trace(ws: Workspace):
    scanner_ctx = _read_json(ws, "scanner_context.json")
    threats = _read_json(ws, "threats.json")
    return (
        "threat-generation",
        scanner_ctx,
        threats,
        ["threat"],
    )


def _parallel_traces(ws: Workspace):
    threats = _read_json(ws, "threats.json")
    scanner_ctx = _read_json(ws, "scanner_context.json")
    trees = _read_json(ws, "attack_trees.json")
    mappings = _read_json(ws, "ttp_mappings.json")
    mitigations = _read_json(ws, "mitigations.json")
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


def push_ttp_dataset_items(repo_path: str, dataset_name: str = "ttp-mappings", run_dir: str | None = None) -> int:
    """Push individual TTP mappings as Langfuse dataset items for SME labeling.

    Each item has the attack step description as input and the mapped technique
    as output. expected_output is left empty for SMEs to label as correct/incorrect.

    Returns the number of items created.
    """
    if not _client:
        return 0

    ws = _state_workspace(repo_path, run_dir)
    trees_data = _read_json(ws, "attack_trees.json") or {}
    mappings_data = _read_json(ws, "ttp_mappings.json") or {}

    # Build step lookup: id → {title, description}
    steps = {}
    for tree in trees_data.get("attack_trees", []):
        for step in tree.get("steps", []):
            steps[step["id"]] = {
                "title": step.get("title", ""),
                "description": step.get("description", ""),
            }

    # Ensure dataset exists
    try:
        _client.create_dataset(
            name=dataset_name,
            description="TTP embedding mappings for SME review. Label expected_output as {\"correct\": true/false}.",
        )
    except Exception:
        pass  # already exists

    # Create a trace ID to link items to
    trace_id = _client.create_trace_id()

    count = 0
    for mapping in mappings_data.get("ttp_mappings", []):
        step_id = mapping.get("attack_step_id", "")
        step = steps.get(step_id, {})

        _client.create_dataset_item(
            dataset_name=dataset_name,
            input={
                "attack_step_id": step_id,
                "attack_step_title": step.get("title", ""),
                "attack_step_description": step.get("description", ""),
            },
            expected_output=None,
            metadata={
                "technique_id": mapping.get("technique_id", ""),
                "technique_name": mapping.get("technique_name", ""),
                "similarity_score": mapping.get("similarity_score"),
                "reviewer_overrode_top1": mapping.get("reviewer_overrode_top1", False),
                "reviewer_reasoning": mapping.get("reviewer_reasoning", ""),
            },
            source_trace_id=trace_id,
        )
        count += 1

    return count
