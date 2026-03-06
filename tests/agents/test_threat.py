"""Tests for Threat Agent and Threat Verifier."""

import json

import pytest

from threatforest.agents.threat.verifier import verify_threat_output
from threatforest.agents.scanner.agent import STATE_DIR


def _write_state(tmp_path, data):
    state_dir = tmp_path / STATE_DIR
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "threats.json"
    state_file.write_text(json.dumps(data))
    return str(state_file)


class TestVerifyThreatOutput:
    def test_valid_threats_pass(self, tmp_path):
        state_file = _write_state(tmp_path, {
            "threats": [
                {"id": "T001", "title": "SQL Injection", "description": "desc", "threat_source": "generated", "priority": "high", "affected_components": ["API"]},
                {"id": "T002", "title": "Auth Bypass", "description": "desc", "threat_source": "generated", "priority": "high", "affected_components": ["Auth"]},
                {"id": "T003", "title": "SSRF", "description": "desc", "threat_source": "generated", "priority": "medium", "affected_components": ["Backend"]},
            ]
        })
        passed, feedback = verify_threat_output(state_file)
        assert passed is True

    def test_too_few_threats_fails(self, tmp_path):
        state_file = _write_state(tmp_path, {
            "threats": [
                {"id": "T001", "title": "SQL Injection", "description": "d", "priority": "high", "affected_components": ["API"]},
            ]
        })
        passed, feedback = verify_threat_output(state_file)
        assert passed is False
        assert "at least" in feedback

    def test_empty_threats_fails(self, tmp_path):
        state_file = _write_state(tmp_path, {"threats": []})
        passed, feedback = verify_threat_output(state_file)
        assert passed is False

    def test_missing_affected_components_fails(self, tmp_path):
        state_file = _write_state(tmp_path, {
            "threats": [
                {"id": "T001", "title": "t", "description": "d", "priority": "high", "affected_components": ["X"]},
                {"id": "T002", "title": "t", "description": "d", "priority": "high", "affected_components": ["X"]},
                {"id": "T003", "title": "t", "description": "d", "priority": "low", "affected_components": []},
            ]
        })
        passed, feedback = verify_threat_output(state_file)
        assert passed is False
        assert "affected_components" in feedback

    def test_no_title_or_description_fails(self, tmp_path):
        state_file = _write_state(tmp_path, {
            "threats": [
                {"id": "T001", "title": "", "description": "", "priority": "high", "affected_components": ["X"]},
                {"id": "T002", "title": "t", "description": "d", "priority": "high", "affected_components": ["X"]},
                {"id": "T003", "title": "t", "description": "d", "priority": "medium", "affected_components": ["X"]},
            ]
        })
        passed, feedback = verify_threat_output(state_file)
        assert passed is False
        assert "no title" in feedback.lower()

    def test_missing_file_fails(self, tmp_path):
        passed, feedback = verify_threat_output(str(tmp_path / "nope.json"))
        assert passed is False

    def test_invalid_json_fails(self, tmp_path):
        state_dir = tmp_path / STATE_DIR
        state_dir.mkdir(parents=True, exist_ok=True)
        f = state_dir / "threats.json"
        f.write_text("{bad json")
        passed, feedback = verify_threat_output(str(f))
        assert passed is False
        assert "JSON" in feedback

    def test_user_provided_threats_pass(self, tmp_path):
        """User-provided threats should pass verification too."""
        state_file = _write_state(tmp_path, {
            "threats": [
                {"id": "T001", "title": "Custom threat", "description": "User wrote this", "priority": "high", "threat_source": "user_provided", "affected_components": ["Service A"]},
                {"id": "T002", "title": "Another", "description": "Also user", "priority": "medium", "threat_source": "user_provided", "affected_components": ["Service B"]},
                {"id": "T003", "title": "Third", "description": "User", "priority": "low", "threat_source": "user_provided", "affected_components": ["DB"]},
            ]
        })
        passed, feedback = verify_threat_output(state_file)
        assert passed is True
