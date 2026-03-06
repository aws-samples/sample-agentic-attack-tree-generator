"""Report Verifier — deterministic completeness check on the final report."""

from pathlib import Path

from threatforest.agents.report.agent import OUTPUT_DIR, OUTPUT_FILE

REQUIRED_SECTIONS = [
    "Executive Summary",
    "Project Context",
    "Threats",
    "Attack Trees",
    "ATT&CK Mappings",
    "Mitigations",
    "Coverage Summary",
]


def verify_report_output(repo_path: str) -> tuple[bool, str]:
    """Verify the report contains all required sections.

    Returns:
        (passed, feedback)
    """
    report_file = Path(repo_path) / OUTPUT_DIR / OUTPUT_FILE

    if not report_file.exists():
        return False, "Report file does not exist"

    content = report_file.read_text()

    if len(content.strip()) < 100:
        return False, "Report is too short (< 100 chars)"

    missing = [s for s in REQUIRED_SECTIONS if s.lower() not in content.lower()]
    if missing:
        return False, f"Missing sections: {', '.join(missing)}"

    return True, "Report is complete"
