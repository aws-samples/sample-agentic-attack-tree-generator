"""Tests for types/ data models — serialization, defaults, validation."""

import dataclasses
import json

from threatforest.types.state import NodeResult
from threatforest.types.project import ProjectContext
from threatforest.types.threat import Threat
from threatforest.types.attack_tree import AttackTree, AttackStep
from threatforest.types.ttp import TTPMapping, TTPCandidate
from threatforest.types.mitigation import Mitigation, ControlCandidate, Evidence
from threatforest.types.quality import QualityWarning


class TestNodeResult:
    def test_defaults(self):
        r = NodeResult(state_file="f.json", summary="ok", route="pass")
        assert r.retry_count == 0
        assert r.max_retries == 2
        assert r.feedback is None

    def test_should_retry(self):
        r = NodeResult(state_file="f.json", summary="", route="reject", retry_count=1)
        assert r.should_retry is True

    def test_over_budget(self):
        r = NodeResult(state_file="f.json", summary="", route="reject", retry_count=2)
        assert r.over_budget is True
        assert r.should_retry is False

    def test_pass_not_retry(self):
        r = NodeResult(state_file="f.json", summary="", route="pass")
        assert r.should_retry is False
        assert r.over_budget is False

    def test_serializable(self):
        r = NodeResult(state_file="f.json", summary="ok", route="pass")
        d = dataclasses.asdict(r)
        json_str = json.dumps(d)
        assert "f.json" in json_str


class TestProjectContext:
    def test_defaults(self):
        ctx = ProjectContext()
        assert ctx.tech_stack == ""
        assert ctx.services == []
        assert ctx.security_controls == {}

    def test_serializable(self):
        ctx = ProjectContext(tech_stack="python", cloud_provider="aws", services=["lambda", "s3"])
        d = dataclasses.asdict(ctx)
        assert d["cloud_provider"] == "aws"
        assert json.dumps(d)


class TestThreat:
    def test_defaults(self):
        t = Threat()
        assert t.affected_components == []

    def test_serializable(self):
        t = Threat(id="T1", title="SQL Injection", threat_source="generated")
        assert json.dumps(dataclasses.asdict(t))


class TestAttackTree:
    def test_defaults(self):
        tree = AttackTree()
        assert tree.steps == []

    def test_with_steps(self):
        step = AttackStep(id="S1", description="Exploit API", parent_id="root", is_leaf=True)
        tree = AttackTree(id="AT1", threat_id="T1", root_goal="Steal data", steps=[step])
        d = dataclasses.asdict(tree)
        assert len(d["steps"]) == 1
        assert json.dumps(d)


class TestTTPMapping:
    def test_defaults(self):
        m = TTPMapping()
        assert m.top_k_candidates == []
        assert m.reviewer_overrode_top1 is False

    def test_with_candidates(self):
        c = TTPCandidate(technique_id="T1059", technique_name="Command and Scripting", similarity_score=0.92, rank=1)
        m = TTPMapping(attack_step_id="S1", technique_id="T1059", top_k_candidates=[c])
        d = dataclasses.asdict(m)
        assert d["top_k_candidates"][0]["rank"] == 1
        assert json.dumps(d)


class TestMitigation:
    def test_defaults(self):
        m = Mitigation()
        assert m.evidence == []
        assert m.control_candidates == []

    def test_with_evidence(self):
        e = Evidence(source_type="control_catalog", source_ref="CC-001", excerpt="Enable encryption", relevance="Addresses data at rest")
        c = ControlCandidate(control_id="CC-001", control_name="Encrypt S3", similarity_score=0.88, rank=1)
        m = Mitigation(attack_step_id="S1", evidence=[e], control_candidates=[c], selected_control_id="CC-001")
        d = dataclasses.asdict(m)
        assert len(d["evidence"]) == 1
        assert json.dumps(d)


class TestQualityWarning:
    def test_serializable(self):
        w = QualityWarning(node_id="tree_verifier", message="Over retry budget", severity="medium")
        assert json.dumps(dataclasses.asdict(w))
