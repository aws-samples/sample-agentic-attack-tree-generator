"""Tree Verifier — checks structure validity and feasibility of attack trees."""

import json
from pathlib import Path


def verify_tree_output(state_file: str, scanner_state_file: str = "") -> tuple[bool, str]:
    """Verify attack trees for structural validity and feasibility.

    Checks:
    1. Structure: valid JSON, has trees, each tree has steps with valid parent refs
    2. Feasibility: if scanner context available, flags steps that reference
       technologies not in the project's tech stack

    Returns:
        (passed, feedback)
    """
    path = Path(state_file)
    if not path.exists():
        return False, "State file does not exist"

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return False, f"State file is not valid JSON: {e}"

    trees = data.get("attack_trees", [])
    if not trees:
        return False, "No attack trees generated"

    # --- Structural checks ---
    for tree in trees:
        tree_id = tree.get("id", "?")
        steps = tree.get("steps", [])

        if not steps:
            return False, f"Tree {tree_id} has no steps"

        if not tree.get("root_goal"):
            return False, f"Tree {tree_id} has no root_goal"

        step_ids = {s.get("id") for s in steps}
        roots = 0
        for step in steps:
            pid = step.get("parent_id", "")
            if not pid:
                roots += 1
            elif pid not in step_ids:
                return False, f"Tree {tree_id}: step '{step.get('id')}' references unknown parent '{pid}'"

        if roots == 0:
            return False, f"Tree {tree_id} has no root step (step with empty parent_id)"

    # --- Feasibility check (optional, needs scanner context) ---
    if scanner_state_file:
        scanner_path = Path(scanner_state_file)
        if scanner_path.exists():
            try:
                scanner_data = json.loads(scanner_path.read_text())
                tech_stack = scanner_data.get("tech_stack", "").lower()
                unfeasible = _check_feasibility(trees, tech_stack)
                if unfeasible:
                    return False, f"Unfeasible steps detected: {'; '.join(unfeasible)}"
            except (json.JSONDecodeError, OSError):
                pass  # skip feasibility if scanner state is unreadable

    return True, "Attack trees are valid and feasible"


def _check_feasibility(trees: list, tech_stack: str) -> list[str]:
    """Flag steps that reference technologies clearly absent from the tech stack."""
    # Only flag obvious mismatches — e.g., "exploit Java deserialization" in a Python-only project
    TECH_MARKERS = {
        "java": ["java deserialization", "java rmi", "jndi injection", "spring actuator"],
        "php": ["php object injection", "php deserialization", "php type juggling"],
        ".net": [".net remoting", "viewstate deserialization", "aspx webshell"],
        "ruby": ["ruby marshal", "erb injection", "rails mass assignment"],
    }

    issues = []
    for tech, markers in TECH_MARKERS.items():
        if tech in tech_stack:
            continue  # tech is present, skip
        for tree in trees:
            for step in tree.get("steps", []):
                desc = step.get("description", "").lower()
                for marker in markers:
                    if marker in desc:
                        issues.append(
                            f"Tree {tree.get('id')}, step {step.get('id')}: "
                            f"references '{marker}' but tech stack has no {tech}"
                        )
    return issues
