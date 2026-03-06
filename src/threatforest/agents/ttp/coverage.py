"""TTP Coverage Check — deterministic, no LLM.

Checks that every attack step in every tree has exactly one final TTP mapping.
"""

import json
from pathlib import Path

from threatforest.agents.scanner.agent import STATE_DIR


def verify_ttp_coverage(repo_path: str) -> tuple[bool, str]:
    """Check that every attack step has a TTP mapping.

    Returns:
        (passed, feedback)
    """
    state_dir = Path(repo_path) / STATE_DIR
    trees_file = state_dir / "attack_trees.json"
    mappings_file = state_dir / "ttp_mappings.json"

    if not trees_file.exists():
        return False, "attack_trees.json does not exist"
    if not mappings_file.exists():
        return False, "ttp_mappings.json does not exist"

    try:
        trees_data = json.loads(trees_file.read_text())
        raw = mappings_file.read_text()
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
