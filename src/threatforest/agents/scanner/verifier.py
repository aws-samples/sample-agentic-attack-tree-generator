"""Context Verifier — checks Scanner Agent output for completeness."""

import json
from pathlib import Path

from threatforest.types.project import ProjectContext

REQUIRED_FIELDS = ["tech_stack", "cloud_provider", "services", "auth_mechanisms", "files_analyzed"]


def verify_scanner_output(state_file: str) -> tuple[bool, str]:
    """Verify the scanner's state file is complete.

    Returns:
        (passed, feedback) — passed=True if context is sufficient,
        otherwise feedback describes what's missing.
    """
    path = Path(state_file)
    if not path.exists():
        return False, "State file does not exist"

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return False, f"State file is not valid JSON: {e}"

    missing = [f for f in REQUIRED_FIELDS if not data.get(f)]
    if missing:
        return False, f"Missing or empty fields: {', '.join(missing)}"

    if not data.get("files_analyzed"):
        return False, "No files were analyzed — scanner may have failed to read the repo"

    if not data.get("tech_stack"):
        return False, "Tech stack is empty — scanner did not identify any technologies"

    return True, "Context is complete"
