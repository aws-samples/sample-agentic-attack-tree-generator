"""Tests for Report Generator — verifier checks."""

import pytest
from pathlib import Path

from threatforest.agents.report.verifier import verify_report_output
from threatforest.agents.report.agent import OUTPUT_DIR, OUTPUT_FILE


def _write_report(tmp_path, content):
    out_dir = tmp_path / OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / OUTPUT_FILE).write_text(content)


GOOD_REPORT = """# Threat Model Report

## Executive Summary
This report covers 5 threats across 12 attack steps for the ExampleApp project.

## Project Context
Tech stack: Python/FastAPI, PostgreSQL. Cloud provider: AWS. Services: Lambda, S3, RDS.

## Threats
1. SQL Injection in /api/users — severity: critical — affects: API Gateway, RDS
2. SSRF via image upload — severity: high — affects: Lambda, S3

## Attack Trees
AT001: 6 steps targeting data exfiltration through SQL injection chain.
AT002: 4 steps targeting lateral movement via SSRF.

## MITRE ATT&CK Mappings
| Step | Technique | Name |
|------|-----------|------|
| S1   | T1190     | Exploit Public-Facing Application |
| S2   | T1059     | Command and Scripting Interpreter |

## Mitigations
Priority 1: Add WAF rules to ALB. Evidence: T1190.
Priority 2: Restrict Lambda execution role. Evidence: infra/lambda.tf.

## Coverage Summary
- Threats: 5
- Attack steps: 12
- TTP coverage: 100%
- Mitigation coverage: 100%
"""


class TestReportVerifier:
    def test_good_report_passes(self, tmp_path):
        _write_report(tmp_path, GOOD_REPORT)
        passed, feedback = verify_report_output(str(tmp_path))
        assert passed is True

    def test_missing_file_fails(self, tmp_path):
        passed, feedback = verify_report_output(str(tmp_path))
        assert passed is False
        assert "does not exist" in feedback

    def test_too_short_fails(self, tmp_path):
        _write_report(tmp_path, "# Report\nShort.")
        passed, feedback = verify_report_output(str(tmp_path))
        assert passed is False
        assert "too short" in feedback

    def test_missing_section_fails(self, tmp_path):
        # Remove mitigations section
        bad = GOOD_REPORT.replace("## Mitigations", "## Fixes").replace("## Coverage Summary", "## Coverage Summary")
        _write_report(tmp_path, bad)
        passed, feedback = verify_report_output(str(tmp_path))
        assert passed is False
        assert "Mitigations" in feedback

    def test_missing_multiple_sections(self, tmp_path):
        minimal = "# Report\n\n## Executive Summary\nSome text here that is long enough to pass the length check for the report verifier test.\n"
        _write_report(tmp_path, minimal)
        passed, feedback = verify_report_output(str(tmp_path))
        assert passed is False
        # Should list multiple missing sections
        assert "Project Context" in feedback
