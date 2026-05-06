"""Mitigation Verifier — deterministic quality checks on mitigations."""

import json

from threatforest.agents.scanner.agent import STATE_DIR, resolve_state_dir
from threatforest.workspace import LocalFilesystemWorkspace

BOILERPLATE = {
    "implement proper access controls",
    "follow security best practices",
    "use encryption",
    "apply the principle of least privilege",
    "implement input validation",
    "use secure coding practices",
    "implement monitoring and logging",
}

VALID_REMEDIATION_TYPES = {"quick_win", "short_term", "medium_term", "long_term", "monitoring"}


def verify_mitigation_output(repo_path: str, run_dir: str | None = None) -> tuple[bool, str]:
    """Verify mitigations are actionable, specific, and evidenced.

    Returns:
        (passed, feedback)
    """
    workspace = LocalFilesystemWorkspace(resolve_state_dir(repo_path, run_dir))

    if not workspace.exists("mitigations.json"):
        return False, "mitigations.json does not exist"
    if not workspace.exists("attack_trees.json"):
        return False, "attack_trees.json does not exist"

    try:
        # Fix trailing commas from JSONL append pattern
        raw = workspace.read_text("mitigations.json").replace(",\n]", "\n]").replace(",]", "]")
        mit_data = json.loads(raw)
        trees_data = workspace.read_json("attack_trees.json")
    except (json.JSONDecodeError, OSError) as e:
        return False, f"Failed to read state files: {e}"

    mitigations = mit_data.get("mitigations", [])

    # Collect step IDs that have TTP mappings (only these can have mitigations)
    all_step_ids = set()
    if workspace.exists("ttp_mappings.json"):
        try:
            mappings_data = workspace.read_json("ttp_mappings.json")
            for m in mappings_data.get("ttp_mappings", []):
                sid = m.get("attack_step_id", "")
                if sid:
                    all_step_ids.add(sid)
        except (json.JSONDecodeError, OSError):
            # Fall back to tree step IDs if mappings unreadable
            for tree in trees_data.get("attack_trees", []):
                for step in tree.get("steps", []):
                    all_step_ids.add(step.get("id", ""))
    else:
        for tree in trees_data.get("attack_trees", []):
            for step in tree.get("steps", []):
                all_step_ids.add(step.get("id", ""))

    if not mitigations and all_step_ids:
        return False, "No mitigations produced but attack steps exist"

    # Hard failures — these warrant a retry
    hard_issues = []
    # Soft warnings — logged but won't trigger a costly full-pipeline retry
    warnings = []
    covered_ids = set()

    for i, m in enumerate(mitigations):
        sid = m.get("attack_step_id", "")
        if not sid:
            hard_issues.append(f"Mitigation {i}: missing attack_step_id")
            continue
        covered_ids.add(sid)
        for also in m.get("also_applies_to", []):
            covered_ids.add(also)

        text = m.get("mitigation_text", "")
        if not text:
            hard_issues.append(f"{sid}: empty mitigation_text")
        elif text.lower().strip().rstrip(".") in BOILERPLATE:
            warnings.append(f"{sid}: boilerplate mitigation — '{text}'")

        evidence = m.get("evidence", [])
        if not evidence:
            warnings.append(f"{sid}: no evidence provided")

        if not m.get("priority"):
            warnings.append(f"{sid}: missing priority")

        rtype = m.get("remediation_type", "")
        if not rtype:
            hard_issues.append(f"{sid}: missing remediation_type")
        elif rtype not in VALID_REMEDIATION_TYPES:
            hard_issues.append(f"{sid}: invalid remediation_type '{rtype}' — must be one of {VALID_REMEDIATION_TYPES}")

    missing = all_step_ids - covered_ids
    if missing:
        # Coverage gaps are warnings, not hard failures — per-threat verification
        # inside the parallel pipeline handles retries at the individual threat level.
        warnings.append(f"{len(missing)} steps without mitigations")

    if hard_issues:
        return False, "; ".join(hard_issues)

    feedback = "All mitigations are actionable and evidenced"
    if warnings:
        feedback += f" ({len(warnings)} warnings)"
    return True, feedback
