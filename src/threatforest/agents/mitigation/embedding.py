"""Control Embedding Model — vector search against AWS Control Catalog.

Not an LLM. For AWS projects only. Finds top-K control candidates per attack step.
Non-AWS projects skip this entirely.
"""

import json
from pathlib import Path

from threatforest.agents.scanner.agent import STATE_DIR

STATE_FILE = "control_candidates.json"


def _is_aws_project(repo_path: str) -> bool:
    """Check scanner context for AWS cloud provider."""
    ctx_file = Path(repo_path) / STATE_DIR / "scanner_context.json"
    if not ctx_file.exists():
        return False
    try:
        data = json.loads(ctx_file.read_text())
        return data.get("cloud_provider", "").lower() == "aws"
    except (json.JSONDecodeError, OSError):
        return False


def run_control_embedding(repo_path: str, top_k: int = 5) -> str | None:
    """Run control embedding search. Returns state file path, or None if skipped.

    Skipped for non-AWS projects (architecture: conditional edge).
    """
    state_dir = Path(repo_path) / STATE_DIR
    out_file = state_dir / STATE_FILE

    if not _is_aws_project(repo_path):
        return None

    # Load attack steps from trees
    trees_file = state_dir / "attack_trees.json"
    trees_data = json.loads(trees_file.read_text())

    steps = []
    for tree in trees_data.get("attack_trees", []):
        for step in tree.get("steps", []):
            steps.append({"id": step.get("id", ""), "description": step.get("description", "")})

    if not steps:
        out_file.write_text(json.dumps({"control_candidates": []}))
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

    out_file.write_text(json.dumps({"control_candidates": candidates}, indent=2))
    return str(out_file)
