"""Tests for Scanner Agent and Context Verifier."""

import json
import os
import tempfile

import pytest

from threatforest.agents.scanner.agent import (
    _count_source_files,
    _load_seeded_business_context,
    STATE_DIR,
    STATE_FILE,
)
from threatforest.agents.scanner.verifier import verify_scanner_output


class TestCountSourceFiles:
    def test_empty_dir(self, tmp_path):
        assert _count_source_files(str(tmp_path)) == 0

    def test_counts_source_files(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hi')")
        (tmp_path / "app.js").write_text("console.log('hi')")
        (tmp_path / "readme.md").write_text("# hi")  # not source
        assert _count_source_files(str(tmp_path)) == 2

    def test_skips_excluded_dirs(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "dep.js").write_text("x")
        (tmp_path / "app.py").write_text("x")
        assert _count_source_files(str(tmp_path)) == 1

    def test_small_repo(self, tmp_path):
        for i in range(10):
            (tmp_path / f"file{i}.py").write_text("x")
        assert _count_source_files(str(tmp_path)) == 10

    def test_large_repo_early_exit(self, tmp_path):
        for i in range(60):
            (tmp_path / f"file{i}.py").write_text("x")
        count = _count_source_files(str(tmp_path))
        assert count >= 50


class TestVerifyScannerOutput:
    def _write_state(self, tmp_path, data):
        state_dir = tmp_path / STATE_DIR
        state_dir.mkdir(parents=True, exist_ok=True)
        state_file = state_dir / STATE_FILE
        state_file.write_text(json.dumps(data))
        return str(state_file)

    def test_valid_output_passes(self, tmp_path):
        state_file = self._write_state(tmp_path, {
            "tech_stack": "Python/FastAPI",
            "cloud_provider": "aws",
            "services": ["Lambda"],
            "auth_mechanisms": ["JWT"],
            "files_analyzed": ["README.md"],
            "repo_size_category": "small",
        })
        passed, feedback = verify_scanner_output(state_file)
        assert passed is True

    def test_missing_tech_stack_fails(self, tmp_path):
        state_file = self._write_state(tmp_path, {
            "tech_stack": "",
            "cloud_provider": "aws",
            "services": ["Lambda"],
            "auth_mechanisms": ["JWT"],
            "files_analyzed": ["README.md"],
        })
        passed, feedback = verify_scanner_output(state_file)
        assert passed is False
        assert "tech_stack" in feedback.lower() or "Tech stack" in feedback

    def test_no_files_analyzed_fails(self, tmp_path):
        state_file = self._write_state(tmp_path, {
            "tech_stack": "Python",
            "cloud_provider": "aws",
            "services": ["S3"],
            "auth_mechanisms": ["IAM"],
            "files_analyzed": [],
        })
        passed, feedback = verify_scanner_output(state_file)
        assert passed is False
        assert "files" in feedback.lower()

    def test_missing_file_fails(self, tmp_path):
        passed, feedback = verify_scanner_output(str(tmp_path / "nonexistent.json"))
        assert passed is False
        assert "not exist" in feedback.lower()

    def test_invalid_json_fails(self, tmp_path):
        state_dir = tmp_path / STATE_DIR
        state_dir.mkdir(parents=True, exist_ok=True)
        state_file = state_dir / STATE_FILE
        state_file.write_text("not json{{{")
        passed, feedback = verify_scanner_output(str(state_file))
        assert passed is False
        assert "JSON" in feedback

    def test_missing_required_fields_fails(self, tmp_path):
        state_file = self._write_state(tmp_path, {
            "tech_stack": "Python",
            # missing cloud_provider, services, auth_mechanisms, files_analyzed
        })
        passed, feedback = verify_scanner_output(state_file)
        assert passed is False
        assert "Missing" in feedback


class TestLoadSeededBusinessContext:
    """The scanner reads a pre-seeded state file to surface user-authoritative
    business context in its system prompt. These tests exercise the helper
    that pulls the nested block out of ``scanner_context.json``.
    """

    def test_returns_none_when_file_missing(self, tmp_path):
        assert _load_seeded_business_context(str(tmp_path / "absent.json")) is None

    def test_returns_none_when_no_business_context_key(self, tmp_path):
        state = tmp_path / "scanner_context.json"
        state.write_text(json.dumps({"tech_stack": "Python"}))
        assert _load_seeded_business_context(str(state)) is None

    def test_returns_block_when_present(self, tmp_path):
        bc = {
            "description": "Healthcare intake API storing PHI.",
            "regulatory_frameworks": ["HIPAA", "SOC2"],
            "data_sensitivity": "phi",
            "main_cia_risk": "confidentiality",
        }
        state = tmp_path / "scanner_context.json"
        state.write_text(json.dumps({"business_context": bc}))
        assert _load_seeded_business_context(str(state)) == bc

    def test_returns_none_when_block_is_empty(self, tmp_path):
        state = tmp_path / "scanner_context.json"
        state.write_text(json.dumps({"business_context": {}}))
        # Empty dict is falsy — treat as "nothing to inject".
        assert _load_seeded_business_context(str(state)) is None

    def test_returns_none_on_malformed_json(self, tmp_path):
        state = tmp_path / "scanner_context.json"
        state.write_text("not valid {")
        # Caller should never crash on a bad state file.
        assert _load_seeded_business_context(str(state)) is None

    def test_returns_none_when_block_is_not_a_dict(self, tmp_path):
        state = tmp_path / "scanner_context.json"
        state.write_text(json.dumps({"business_context": "oops a string"}))
        assert _load_seeded_business_context(str(state)) is None
