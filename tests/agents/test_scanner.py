"""Tests for Scanner Agent and Context Verifier."""

import json
import os
import tempfile

import pytest

from threatforest.agents.scanner.agent import _count_source_files, STATE_DIR, STATE_FILE
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
