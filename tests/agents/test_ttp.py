"""Tests for TTP pipeline — embedding, reviewer, coverage check."""

import json

import pytest

from threatforest.agents.ttp.coverage import verify_ttp_coverage
from threatforest.agents.scanner.agent import STATE_DIR


def _write(tmp_path, filename, data):
    state_dir = tmp_path / STATE_DIR
    state_dir.mkdir(parents=True, exist_ok=True)
    f = state_dir / filename
    f.write_text(json.dumps(data))
    return str(f)


TREES = {
    "attack_trees": [{
        "id": "AT001", "threat_id": "T001", "root_goal": "X",
        "steps": [
            {"id": "S1", "description": "root", "parent_id": ""},
            {"id": "S2", "description": "child", "parent_id": "S1"},
            {"id": "S3", "description": "leaf", "parent_id": "S1"},
        ],
    }]
}

FULL_MAPPINGS = {
    "ttp_mappings": [
        {"attack_step_id": "S1", "technique_id": "T1190", "technique_name": "Exploit Public-Facing App", "similarity_score": 0.9, "top_k_candidates": [], "reviewer_overrode_top1": False, "reviewer_reasoning": ""},
        {"attack_step_id": "S2", "technique_id": "T1059", "technique_name": "Command and Scripting", "similarity_score": 0.8, "top_k_candidates": [], "reviewer_overrode_top1": False, "reviewer_reasoning": ""},
        {"attack_step_id": "S3", "technique_id": "T1041", "technique_name": "Exfiltration Over C2", "similarity_score": 0.7, "top_k_candidates": [], "reviewer_overrode_top1": False, "reviewer_reasoning": ""},
    ]
}


class TestTTPCoverageCheck:
    def test_full_coverage_passes(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        _write(tmp_path, "ttp_mappings.json", FULL_MAPPINGS)
        passed, feedback = verify_ttp_coverage(str(tmp_path))
        assert passed is True

    def test_missing_step_fails(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        partial = {"ttp_mappings": FULL_MAPPINGS["ttp_mappings"][:2]}  # missing S3
        _write(tmp_path, "ttp_mappings.json", partial)
        passed, feedback = verify_ttp_coverage(str(tmp_path))
        assert passed is False
        assert "S3" in feedback

    def test_empty_mappings_fails(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        _write(tmp_path, "ttp_mappings.json", {"ttp_mappings": []})
        passed, feedback = verify_ttp_coverage(str(tmp_path))
        assert passed is False

    def test_missing_technique_id_not_counted(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        bad = {"ttp_mappings": [
            {"attack_step_id": "S1", "technique_id": "T1190"},
            {"attack_step_id": "S2", "technique_id": ""},  # empty technique = not mapped
            {"attack_step_id": "S3", "technique_id": "T1041"},
        ]}
        _write(tmp_path, "ttp_mappings.json", bad)
        passed, feedback = verify_ttp_coverage(str(tmp_path))
        assert passed is False
        assert "S2" in feedback

    def test_missing_trees_file_fails(self, tmp_path):
        _write(tmp_path, "ttp_mappings.json", FULL_MAPPINGS)
        passed, feedback = verify_ttp_coverage(str(tmp_path))
        assert passed is False

    def test_missing_mappings_file_fails(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        passed, feedback = verify_ttp_coverage(str(tmp_path))
        assert passed is False

    def test_empty_trees_passes(self, tmp_path):
        """No steps = nothing to map = passes."""
        _write(tmp_path, "attack_trees.json", {"attack_trees": []})
        _write(tmp_path, "ttp_mappings.json", {"ttp_mappings": []})
        passed, feedback = verify_ttp_coverage(str(tmp_path))
        assert passed is True

    def test_multiple_trees(self, tmp_path):
        multi = {"attack_trees": [
            {"id": "AT1", "root_goal": "X", "steps": [
                {"id": "A1", "description": "x", "parent_id": ""},
            ]},
            {"id": "AT2", "root_goal": "Y", "steps": [
                {"id": "B1", "description": "y", "parent_id": ""},
            ]},
        ]}
        mappings = {"ttp_mappings": [
            {"attack_step_id": "A1", "technique_id": "T1190"},
            {"attack_step_id": "B1", "technique_id": "T1059"},
        ]}
        _write(tmp_path, "attack_trees.json", multi)
        _write(tmp_path, "ttp_mappings.json", mappings)
        passed, feedback = verify_ttp_coverage(str(tmp_path))
        assert passed is True
