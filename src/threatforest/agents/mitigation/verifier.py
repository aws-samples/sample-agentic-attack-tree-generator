"""Mitigation Verifier — deterministic quality checks on mitigations."""

import json
from pathlib import Path

from threatforest.agents.scanner.agent import STATE_DIR

BOILERPLATE = {
    "implement proper access controls",
    "follow security best practices",
    "use encryption",
    "apply the principle of least privilege",
    "implement input validation",
    "use secure coding practices",
    "implement monitoring and logging",
}


def verify_mitigation_output(repo_path: str) -> tuple[bool, str]:
    """Verify mitigations are actionable, specific, and evidenced.

    Returns:
        (passed, feedback)
    """
    state_dir = Path(repo_path) / STATE_DIR
    mit_file = state_dir / "mitigations.json"
    trees_file = state_dir / "attack_trees.json"

    if not mit_file.exists():
        return False, "mitigations.json does not exist"
    if not trees_file.exists():
        return False, "attack_trees.json does not exist"

    try:
        raw = mit_file.read_text()
        # Fix trailing commas from JSONL append pattern
        raw = raw.replace(",\n]", "\n]").replace(",]", "]")
        mit_data = json.loads(raw)
        trees_data = json.loads(trees_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return False, f"Failed to read state files: {e}"

    mitigations = mit_data.get("mitigations", [])

    # Collect all step IDs
    all_step_ids = set()
    for tree in trees_data.get("attack_trees", []):
        for step in tree.get("steps", []):
            all_step_ids.add(step.get("id", ""))

    if not mitigations and all_step_ids:
        return False, "No mitigations produced but attack steps exist"

    issues = []
    covered_ids = set()

    for i, m in enumerate(mitigations):
        sid = m.get("attack_step_id", "")
        if not sid:
            issues.append(f"Mitigation {i}: missing attack_step_id")
            continue
        covered_ids.add(sid)
        for also in m.get("also_applies_to", []):
            covered_ids.add(also)

        text = m.get("mitigation_text", "")
        if not text:
            issues.append(f"{sid}: empty mitigation_text")
        elif text.lower().strip().rstrip(".") in BOILERPLATE:
            issues.append(f"{sid}: boilerplate mitigation — '{text}'")

        evidence = m.get("evidence", [])
        if not evidence:
            issues.append(f"{sid}: no evidence provided")

        if not m.get("priority"):
            issues.append(f"{sid}: missing priority")

    missing = all_step_ids - covered_ids
    if missing:
        issues.append(f"Steps without mitigations: {', '.join(sorted(missing))}")

    if issues:
        return False, "; ".join(issues)

    return True, "All mitigations are actionable and evidenced"
