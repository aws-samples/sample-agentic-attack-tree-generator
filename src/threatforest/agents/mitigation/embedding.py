"""Control Embedding Model — vector search against AWS Control Catalog.

Not an LLM. For AWS projects only. Finds top-K control candidates per attack step.
Non-AWS projects skip this entirely.
"""

import json

from threatforest.agents.scanner.agent import STATE_DIR, resolve_state_dir
from threatforest.workspace import LocalFilesystemWorkspace

STATE_FILE = "control_candidates.json"


def _is_aws_project(repo_path: str, run_dir: str | None = None) -> bool:
    """Check scanner context for AWS cloud provider."""
    workspace = LocalFilesystemWorkspace(resolve_state_dir(repo_path, run_dir))
    if not workspace.exists("scanner_context.json"):
        return False
    try:
        data = workspace.read_json("scanner_context.json")
        return data.get("cloud_provider", "").lower() == "aws"
    except (json.JSONDecodeError, OSError):
        return False


def run_control_embedding(repo_path: str, top_k: int = 5, run_dir: str | None = None) -> str | None:
    """Run control embedding search. Returns state file path, or None if skipped.

    Skipped for non-AWS projects (architecture: conditional edge).
    """
    state_dir = resolve_state_dir(repo_path, run_dir)
    workspace = LocalFilesystemWorkspace(state_dir)
    out_file = state_dir / STATE_FILE

    if not _is_aws_project(repo_path, run_dir=run_dir):
        return None

    # Load attack steps from trees
    trees_data = workspace.read_json("attack_trees.json")

    steps = []
    for tree in trees_data.get("attack_trees", []):
        for step in tree.get("steps", []):
            steps.append({"id": step.get("id", ""), "description": step.get("description", "")})

    if not steps:
        workspace.write_json(STATE_FILE, {"control_candidates": []})
        return str(out_file)

    # TODO: Replace with actual AWS Control Catalog embedding search
    # when the catalog embeddings are built. For now, this is a placeholder
    # that produces the correct schema so downstream agents work.
    candidates = []
    for step in steps:
        candidates.append({
            "attack_step_id": step["id"],
            "top_k": [],  # populated when catalog embeddings exist
        })

    workspace.write_json(STATE_FILE, {"control_candidates": candidates})
    return str(out_file)
