"""Tests for Tree Generator and Tree Verifier."""

import json

import pytest

from threatforest.agents.tree.verifier import verify_tree_output, _check_feasibility
from threatforest.agents.scanner.agent import STATE_DIR


def _write(tmp_path, filename, data):
    state_dir = tmp_path / STATE_DIR
    state_dir.mkdir(parents=True, exist_ok=True)
    f = state_dir / filename
    f.write_text(json.dumps(data))
    return str(f)


VALID_TREE = {
    "attack_trees": [{
        "id": "AT001",
        "threat_id": "T001",
        "root_goal": "Steal data",
        "steps": [
            {"id": "S1", "description": "Find endpoint", "parent_id": "", "is_leaf": False},
            {"id": "S2", "description": "Inject payload", "parent_id": "S1", "is_leaf": True},
            {"id": "S3", "description": "Exfiltrate data", "parent_id": "S1", "is_leaf": True},
        ],
    }]
}


class TestVerifyTreeOutput:
    def test_valid_tree_passes(self, tmp_path):
        f = _write(tmp_path, "attack_trees.json", VALID_TREE)
        passed, feedback = verify_tree_output(f)
        assert passed is True

    def test_no_trees_fails(self, tmp_path):
        f = _write(tmp_path, "attack_trees.json", {"attack_trees": []})
        passed, feedback = verify_tree_output(f)
        assert passed is False
        assert "No attack trees" in feedback

    def test_no_steps_fails(self, tmp_path):
        f = _write(tmp_path, "attack_trees.json", {
            "attack_trees": [{"id": "AT1", "root_goal": "X", "steps": []}]
        })
        passed, feedback = verify_tree_output(f)
        assert passed is False
        assert "no steps" in feedback.lower()

    def test_no_root_goal_fails(self, tmp_path):
        f = _write(tmp_path, "attack_trees.json", {
            "attack_trees": [{"id": "AT1", "root_goal": "", "steps": [
                {"id": "S1", "description": "x", "parent_id": "", "is_leaf": True}
            ]}]
        })
        passed, feedback = verify_tree_output(f)
        assert passed is False
        assert "root_goal" in feedback

    def test_invalid_parent_ref_fails(self, tmp_path):
        f = _write(tmp_path, "attack_trees.json", {
            "attack_trees": [{"id": "AT1", "root_goal": "X", "steps": [
                {"id": "S1", "description": "root", "parent_id": "", "is_leaf": False},
                {"id": "S2", "description": "child", "parent_id": "NONEXISTENT", "is_leaf": True},
            ]}]
        })
        passed, feedback = verify_tree_output(f)
        assert passed is False
        assert "unknown parent" in feedback.lower()

    def test_no_root_step_fails(self, tmp_path):
        f = _write(tmp_path, "attack_trees.json", {
            "attack_trees": [{"id": "AT1", "root_goal": "X", "steps": [
                {"id": "S1", "description": "x", "parent_id": "S2", "is_leaf": False},
                {"id": "S2", "description": "y", "parent_id": "S1", "is_leaf": True},
            ]}]
        })
        passed, feedback = verify_tree_output(f)
        assert passed is False
        assert "no root step" in feedback.lower()

    def test_missing_file_fails(self, tmp_path):
        passed, feedback = verify_tree_output(str(tmp_path / "nope.json"))
        assert passed is False

    def test_invalid_json_fails(self, tmp_path):
        state_dir = tmp_path / STATE_DIR
        state_dir.mkdir(parents=True, exist_ok=True)
        f = state_dir / "attack_trees.json"
        f.write_text("not json")
        passed, feedback = verify_tree_output(str(f))
        assert passed is False


class TestFeasibilityCheck:
    def test_no_mismatch_returns_empty(self):
        trees = [{"id": "AT1", "steps": [
            {"id": "S1", "description": "Exploit Python pickle deserialization"}
        ]}]
        assert _check_feasibility(trees, "python/fastapi") == []

    def test_java_mismatch_in_python_project(self):
        trees = [{"id": "AT1", "steps": [
            {"id": "S1", "description": "Exploit Java deserialization vulnerability"}
        ]}]
        issues = _check_feasibility(trees, "python/fastapi with postgresql")
        assert len(issues) == 1
        assert "java deserialization" in issues[0].lower()

    def test_no_flag_when_tech_present(self):
        trees = [{"id": "AT1", "steps": [
            {"id": "S1", "description": "Exploit Java deserialization vulnerability"}
        ]}]
        assert _check_feasibility(trees, "java/spring boot") == []

    def test_feasibility_integrated_with_verifier(self, tmp_path):
        tree_file = _write(tmp_path, "attack_trees.json", {
            "attack_trees": [{"id": "AT1", "root_goal": "X", "steps": [
                {"id": "S1", "description": "root", "parent_id": "", "is_leaf": False},
                {"id": "S2", "description": "Exploit PHP object injection", "parent_id": "S1", "is_leaf": True},
            ]}]
        })
        scanner_file = _write(tmp_path, "scanner_context.json", {
            "tech_stack": "python/django",
            "cloud_provider": "aws",
            "services": [],
            "auth_mechanisms": [],
            "files_analyzed": ["x"],
        })
        passed, feedback = verify_tree_output(tree_file, scanner_file)
        assert passed is False
        assert "php object injection" in feedback.lower()

    def test_feasibility_passes_when_no_scanner(self, tmp_path):
        """Without scanner context, feasibility check is skipped."""
        tree_file = _write(tmp_path, "attack_trees.json", {
            "attack_trees": [{"id": "AT1", "root_goal": "X", "steps": [
                {"id": "S1", "description": "root", "parent_id": "", "is_leaf": False},
                {"id": "S2", "description": "Exploit PHP object injection", "parent_id": "S1", "is_leaf": True},
            ]}]
        })
        passed, feedback = verify_tree_output(tree_file)
        assert passed is True  # no scanner = no feasibility check
