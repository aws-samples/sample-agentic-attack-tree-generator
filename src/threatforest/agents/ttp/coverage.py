"""TTP Coverage Check — deterministic, no LLM.

Checks that every attack step in every tree has exactly one final TTP mapping.
"""

import json

from threatforest.agents.scanner.agent import STATE_DIR, resolve_state_dir
from threatforest.workspace import LocalFilesystemWorkspace


def verify_ttp_coverage(repo_path: str, run_dir: str | None = None) -> tuple[bool, str]:
    """Check that every attack step has a TTP mapping.

    Returns:
        (passed, feedback)
    """
    workspace = LocalFilesystemWorkspace(resolve_state_dir(repo_path, run_dir))

    if not workspace.exists("attack_trees.json"):
        return False, "attack_trees.json does not exist"
    if not workspace.exists("ttp_mappings.json"):
        return False, "ttp_mappings.json does not exist"

    try:
        trees_data = workspace.read_json("attack_trees.json")
        raw = workspace.read_text("ttp_mappings.json")
        raw = raw.replace(",\n]", "\n]").replace(",]", "]")
        mappings_data = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        return False, f"Failed to read state files: {e}"

    # Collect all step IDs from trees
    all_step_ids = set()
    for tree in trees_data.get("attack_trees", []):
        for step in tree.get("steps", []):
            all_step_ids.add(step.get("id", ""))

    # Collect mapped step IDs
    mapped_ids = set()
    for m in mappings_data.get("ttp_mappings", []):
        sid = m.get("attack_step_id", "")
        tid = m.get("technique_id", "")
        if sid and tid:
            mapped_ids.add(sid)

    missing = all_step_ids - mapped_ids
    if missing:
        return False, f"Steps missing TTP mappings: {', '.join(sorted(missing))}"

    return True, "All steps have TTP mappings"
