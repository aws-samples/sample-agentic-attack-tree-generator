"""Tests for Mitigation pipeline — embedding, verifier."""

import json

import pytest

from threatforest.agents.mitigation.embedding import run_control_embedding, _is_aws_project
from threatforest.agents.mitigation.verifier import verify_mitigation_output
from threatforest.agents.scanner.agent import STATE_DIR


def _write(tmp_path, filename, data):
    state_dir = tmp_path / STATE_DIR
    state_dir.mkdir(parents=True, exist_ok=True)
    f = state_dir / filename
    f.write_text(json.dumps(data))
    return str(f)


TREES = {
    "attack_trees": [{
        "id": "AT001", "root_goal": "X",
        "steps": [
            {"id": "S1", "description": "root step", "parent_id": ""},
            {"id": "S2", "description": "child step", "parent_id": "S1"},
        ],
    }]
}

GOOD_MITIGATIONS = {
    "mitigations": [
        {
            "attack_step_id": "S1", "technique_id": "T1190",
            "mitigation_text": "Add WAF rules to the ALB in front of /api/users",
            "implementation_guidance": "Deploy AWS WAF with SQL injection rule set",
            "control_candidates": [], "selected_control_id": "", "priority": 1,
            "evidence": [{"source_type": "attack_technique", "source_ref": "T1190", "excerpt": "x", "relevance": "y"}],
        },
        {
            "attack_step_id": "S2", "technique_id": "T1059",
            "mitigation_text": "Restrict Lambda execution role to s3:GetObject on the data bucket only",
            "implementation_guidance": "Update IAM policy in infra/lambda.tf",
            "control_candidates": [], "selected_control_id": "", "priority": 2,
            "evidence": [{"source_type": "project_file", "source_ref": "infra/lambda.tf", "excerpt": "x", "relevance": "y"}],
        },
    ]
}


# --- Embedding conditional tests ---

class TestControlEmbedding:
    def test_aws_project_detected(self, tmp_path):
        _write(tmp_path, "scanner_context.json", {"cloud_provider": "aws"})
        assert _is_aws_project(str(tmp_path)) is True

    def test_non_aws_skipped(self, tmp_path):
        _write(tmp_path, "scanner_context.json", {"cloud_provider": "gcp"})
        assert _is_aws_project(str(tmp_path)) is False

    def test_hybrid_skipped(self, tmp_path):
        _write(tmp_path, "scanner_context.json", {"cloud_provider": "hybrid"})
        assert _is_aws_project(str(tmp_path)) is False

    def test_run_skips_non_aws(self, tmp_path):
        _write(tmp_path, "scanner_context.json", {"cloud_provider": "gcp"})
        result = run_control_embedding(str(tmp_path))
        assert result is None

    def test_run_produces_candidates_for_aws(self, tmp_path):
        _write(tmp_path, "scanner_context.json", {"cloud_provider": "aws"})
        _write(tmp_path, "attack_trees.json", TREES)
        result = run_control_embedding(str(tmp_path))
        assert result is not None
        data = json.loads((tmp_path / STATE_DIR / "control_candidates.json").read_text())
        assert len(data["control_candidates"]) == 2


# --- Verifier tests ---

class TestMitigationVerifier:
    def test_good_mitigations_pass(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        _write(tmp_path, "mitigations.json", GOOD_MITIGATIONS)
        passed, feedback = verify_mitigation_output(str(tmp_path))
        assert passed is True

    def test_missing_step_fails(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        partial = {"mitigations": [GOOD_MITIGATIONS["mitigations"][0]]}  # only S1
        _write(tmp_path, "mitigations.json", partial)
        passed, feedback = verify_mitigation_output(str(tmp_path))
        assert passed is False
        assert "S2" in feedback

    def test_boilerplate_rejected(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        bad = {"mitigations": [
            {**GOOD_MITIGATIONS["mitigations"][0], "mitigation_text": "implement proper access controls"},
            GOOD_MITIGATIONS["mitigations"][1],
        ]}
        _write(tmp_path, "mitigations.json", bad)
        passed, feedback = verify_mitigation_output(str(tmp_path))
        assert passed is False
        assert "boilerplate" in feedback

    def test_no_evidence_rejected(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        bad = {"mitigations": [
            {**GOOD_MITIGATIONS["mitigations"][0], "evidence": []},
            GOOD_MITIGATIONS["mitigations"][1],
        ]}
        _write(tmp_path, "mitigations.json", bad)
        passed, feedback = verify_mitigation_output(str(tmp_path))
        assert passed is False
        assert "no evidence" in feedback

    def test_missing_priority_rejected(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        bad = {"mitigations": [
            {**GOOD_MITIGATIONS["mitigations"][0], "priority": 0},
            GOOD_MITIGATIONS["mitigations"][1],
        ]}
        _write(tmp_path, "mitigations.json", bad)
        passed, feedback = verify_mitigation_output(str(tmp_path))
        assert passed is False
        assert "priority" in feedback

    def test_empty_mitigations_with_steps_fails(self, tmp_path):
        _write(tmp_path, "attack_trees.json", TREES)
        _write(tmp_path, "mitigations.json", {"mitigations": []})
        passed, feedback = verify_mitigation_output(str(tmp_path))
        assert passed is False

    def test_empty_trees_empty_mitigations_passes(self, tmp_path):
        _write(tmp_path, "attack_trees.json", {"attack_trees": []})
        _write(tmp_path, "mitigations.json", {"mitigations": []})
        passed, feedback = verify_mitigation_output(str(tmp_path))
        assert passed is True
