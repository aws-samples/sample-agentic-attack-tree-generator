"""Threat Verifier — checks threat agent output for quality."""

import json
from pathlib import Path

MIN_THREATS = 3


def verify_threat_output(state_file: str) -> tuple[bool, str]:
    """Verify the threat agent's state file has quality threats.

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

    threats = data.get("threats", [])
    if len(threats) < MIN_THREATS:
        return False, f"Only {len(threats)} threats generated, need at least {MIN_THREATS}"

    for i, t in enumerate(threats):
        if not t.get("title") and not t.get("description"):
            return False, f"Threat {i} has no title or description"
        if not t.get("affected_components"):
            return False, f"Threat '{t.get('id', i)}' has no affected_components — threats must be tied to specific components"
        if not t.get("priority") and not t.get("severity"):
            return False, f"Threat '{t.get('id', i)}' has no priority — must be 'critical', 'high', 'medium', or 'low'"

    return True, "Threats are valid"
