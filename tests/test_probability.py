"""Unit tests for the probability stage.

Covers the three layers we implemented:
  1. factor_prior — monotonic in each factor.
  2. update_posterior — bounded [0, 1] and monotonic in each evidence knob.
  3. compute_reach — fact node = 1.0, child <= parent, multiplicative chain.

Plus a small integration test of run_probability_stage on a temp state dir.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatforest.agents.probability.prior import factor_prior, _sigmoid
from threatforest.agents.probability.posterior import (
    compute_reach,
    detect_tech_stack_mismatch,
    update_posterior,
)
from threatforest.agents.probability.stage import (
    compute_probabilities,
    run_probability_stage,
)


# ----------------------------------------------------------------------
# factor_prior
# ----------------------------------------------------------------------

def test_prior_neutral_when_no_factors():
    p, rationale = factor_prior({"id": "S1", "description": "anything"})
    # BASE_LOGIT = -0.5 → sigmoid(-0.5) ≈ 0.378
    assert 0.35 < p < 0.40
    assert "neutral" in rationale


def test_prior_in_unit_interval():
    for skill in ("low", "med", "high", ""):
        for access in ("none", "authenticated", "privileged", ""):
            for detect in ("low", "med", "high", ""):
                for maturity in ("theoretical", "poc", "weaponised", ""):
                    p, _ = factor_prior({
                        "skill_required": skill,
                        "access_required": access,
                        "detectability": detect,
                        "exploit_maturity": maturity,
                    })
                    assert 0.0 <= p <= 1.0


def test_prior_monotonic_in_skill():
    base = {"access_required": "none", "detectability": "med", "exploit_maturity": "poc"}
    p_low, _ = factor_prior({**base, "skill_required": "low"})
    p_med, _ = factor_prior({**base, "skill_required": "med"})
    p_high, _ = factor_prior({**base, "skill_required": "high"})
    assert p_low > p_med > p_high


def test_prior_monotonic_in_access():
    base = {"skill_required": "med", "detectability": "med", "exploit_maturity": "poc"}
    p_none, _ = factor_prior({**base, "access_required": "none"})
    p_auth, _ = factor_prior({**base, "access_required": "authenticated"})
    p_priv, _ = factor_prior({**base, "access_required": "privileged"})
    assert p_none > p_auth > p_priv


def test_prior_unknown_value_treated_as_neutral():
    # Unknown value should not crash and should behave like the missing case.
    p_unknown, _ = factor_prior({"skill_required": "wizard"})
    p_missing, _ = factor_prior({})
    assert p_unknown == pytest.approx(p_missing)


# ----------------------------------------------------------------------
# update_posterior
# ----------------------------------------------------------------------

def test_posterior_bounds():
    for prior in (0.01, 0.5, 0.99):
        for sim in (0.0, 0.5, 1.0):
            for prio in (None, 1, 3, 5):
                p, _ = update_posterior(
                    prior,
                    ttp_similarity=sim,
                    mitigation_priority=prio,
                    feasibility_note="maybe",
                    tech_stack_mismatch=True,
                )
                assert 0.0 <= p <= 1.0


def test_posterior_no_evidence_returns_prior():
    p_in = 0.42
    p_out, rationale = update_posterior(p_in)
    assert p_out == pytest.approx(p_in, abs=1e-6)
    assert "no posterior evidence" in rationale


def test_posterior_monotonic_in_similarity():
    prior = 0.4
    p_low, _ = update_posterior(prior, ttp_similarity=0.0)
    p_mid, _ = update_posterior(prior, ttp_similarity=0.5)
    p_high, _ = update_posterior(prior, ttp_similarity=1.0)
    assert p_low < p_mid <= p_high  # mid may equal high if clipped


def test_posterior_monotonic_in_mitigation_priority():
    prior = 0.6
    p_prio1, _ = update_posterior(prior, mitigation_priority=1)
    p_prio3, _ = update_posterior(prior, mitigation_priority=3)
    p_nopriority, _ = update_posterior(prior, mitigation_priority=5)  # 4+ → 0
    assert p_prio1 < p_prio3 < p_nopriority


def test_posterior_feasibility_note_discounts():
    prior = 0.6
    p_clean, _ = update_posterior(prior)
    p_flagged, _ = update_posterior(prior, feasibility_note="tech mismatch")
    assert p_flagged < p_clean


def test_posterior_tech_stack_mismatch_discounts():
    prior = 0.6
    p_ok, _ = update_posterior(prior, tech_stack_mismatch=False)
    p_mismatch, _ = update_posterior(prior, tech_stack_mismatch=True)
    assert p_mismatch < p_ok


def test_posterior_rationale_lists_applied_evidence():
    _, r = update_posterior(
        0.5,
        ttp_similarity=0.9,
        mitigation_priority=2,
        feasibility_note="note",
        tech_stack_mismatch=True,
    )
    assert "ttp_similarity" in r
    assert "mitigation_priority" in r
    assert "feasibility_note" in r
    assert "tech_stack_mismatch" in r


# ----------------------------------------------------------------------
# detect_tech_stack_mismatch
# ----------------------------------------------------------------------

def test_tech_stack_mismatch_detected_when_tech_absent():
    assert detect_tech_stack_mismatch(
        "exploit java deserialization flaw", tech_stack="python, node.js"
    ) is True


def test_tech_stack_mismatch_false_when_tech_present():
    assert detect_tech_stack_mismatch(
        "exploit java deserialization flaw", tech_stack="java, spring"
    ) is False


def test_tech_stack_mismatch_false_on_generic_description():
    assert detect_tech_stack_mismatch("brute force login", tech_stack="python") is False


# ----------------------------------------------------------------------
# compute_reach
# ----------------------------------------------------------------------

def test_reach_fact_node_is_one():
    steps = [
        {"id": "S1", "parent_id": "", "category": "fact", "probability": 0.9},
        {"id": "S2", "parent_id": "S1", "probability": 0.5},
    ]
    reach = compute_reach(steps)
    assert reach["S1"] == pytest.approx(1.0)


def test_reach_multiplicative_chain():
    steps = [
        {"id": "S1", "parent_id": "", "category": "fact", "probability": 1.0},
        {"id": "S2", "parent_id": "S1", "probability": 0.5},
        {"id": "S3", "parent_id": "S2", "probability": 0.4},
        {"id": "S4", "parent_id": "S3", "probability": 0.2},
    ]
    reach = compute_reach(steps)
    assert reach["S2"] == pytest.approx(0.5)
    assert reach["S3"] == pytest.approx(0.5 * 0.4)
    assert reach["S4"] == pytest.approx(0.5 * 0.4 * 0.2)


def test_reach_child_bounded_by_parent():
    steps = [
        {"id": "S1", "parent_id": "", "category": "fact", "probability": 1.0},
        {"id": "S2", "parent_id": "S1", "probability": 0.7},
        {"id": "S3", "parent_id": "S2", "probability": 0.8},
        {"id": "S4", "parent_id": "S2", "probability": 0.2},
    ]
    reach = compute_reach(steps)
    for sid in ("S2", "S3", "S4"):
        parent_id = next(s["parent_id"] for s in steps if s["id"] == sid)
        assert reach[sid] <= reach[parent_id] + 1e-9


def test_reach_in_unit_interval():
    steps = [
        {"id": "S1", "parent_id": "", "category": "fact", "probability": 1.0},
        {"id": "S2", "parent_id": "S1", "probability": 0.9},
        {"id": "S3", "parent_id": "S2", "probability": 0.9},
    ]
    reach = compute_reach(steps)
    for v in reach.values():
        assert 0.0 <= v <= 1.0


def test_reach_handles_missing_parent_gracefully():
    # Broken tree where S2's parent doesn't exist — should not crash; treated
    # as root (reach=1.0 * probability).
    steps = [
        {"id": "S1", "parent_id": "", "category": "fact", "probability": 1.0},
        {"id": "S2", "parent_id": "GHOST", "probability": 0.5},
    ]
    reach = compute_reach(steps)
    assert reach["S1"] == pytest.approx(1.0)
    assert reach["S2"] == pytest.approx(0.5)


# ----------------------------------------------------------------------
# compute_probabilities (integration)
# ----------------------------------------------------------------------

def test_compute_probabilities_sets_all_fields():
    trees = [{
        "id": "AT001",
        "threat_id": "T1",
        "root_goal": "x",
        "steps": [
            {"id": "S1", "parent_id": "", "category": "fact", "description": "attacker"},
            {
                "id": "S2",
                "parent_id": "S1",
                "description": "step",
                "skill_required": "med",
                "access_required": "none",
                "detectability": "med",
                "exploit_maturity": "poc",
            },
        ],
    }]
    compute_probabilities(trees, ttp_by_step={}, mitigations_by_step={}, tech_stack="python")

    s1, s2 = trees[0]["steps"]
    assert s1["probability"] == 1.0
    assert s1["reach_probability"] == 1.0
    assert 0.0 <= s2["probability"] <= 1.0
    # With no evidence, reach == probability since parent is fact (reach=1).
    assert s2["reach_probability"] == pytest.approx(s2["probability"])
    assert "prior" in s2["probability_rationale"]


def test_compute_probabilities_boosts_on_high_ttp_match():
    step_base = {
        "parent_id": "S1",
        "description": "exfil",
        "skill_required": "med",
        "access_required": "none",
        "detectability": "med",
        "exploit_maturity": "poc",
    }
    trees_lo = [{"id": "AT", "steps": [
        {"id": "S1", "parent_id": "", "category": "fact", "description": "a"},
        {"id": "S2", **step_base},
    ]}]
    trees_hi = [{"id": "AT", "steps": [
        {"id": "S1", "parent_id": "", "category": "fact", "description": "a"},
        {"id": "S2", **step_base},
    ]}]
    compute_probabilities(trees_lo, ttp_by_step={"S2": {"similarity_score": 0.1}}, mitigations_by_step={})
    compute_probabilities(trees_hi, ttp_by_step={"S2": {"similarity_score": 0.95}}, mitigations_by_step={})
    assert trees_hi[0]["steps"][1]["probability"] > trees_lo[0]["steps"][1]["probability"]


def test_compute_probabilities_discounts_on_high_priority_mitigation():
    base_step = {
        "id": "S2", "parent_id": "S1", "description": "step",
        "skill_required": "med", "access_required": "none",
        "detectability": "med", "exploit_maturity": "poc",
    }
    trees_no_mit = [{"id": "AT", "steps": [
        {"id": "S1", "parent_id": "", "category": "fact"},
        dict(base_step),
    ]}]
    trees_mit = [{"id": "AT", "steps": [
        {"id": "S1", "parent_id": "", "category": "fact"},
        dict(base_step),
    ]}]
    compute_probabilities(trees_no_mit, ttp_by_step={}, mitigations_by_step={})
    compute_probabilities(trees_mit, ttp_by_step={}, mitigations_by_step={"S2": {"priority": 1}})
    assert trees_mit[0]["steps"][1]["probability"] < trees_no_mit[0]["steps"][1]["probability"]


# ----------------------------------------------------------------------
# run_probability_stage
# ----------------------------------------------------------------------

def test_run_probability_stage_end_to_end(tmp_path: Path):
    state_dir = tmp_path / "run-1" / "state"
    state_dir.mkdir(parents=True)

    (state_dir / "attack_trees.json").write_text(json.dumps({
        "attack_trees": [{
            "id": "AT001",
            "threat_id": "T1",
            "root_goal": "goal",
            "steps": [
                {"id": "S1", "parent_id": "", "category": "fact", "description": "attacker"},
                {
                    "id": "S2", "parent_id": "S1", "description": "do thing",
                    "skill_required": "med", "access_required": "none",
                    "detectability": "med", "exploit_maturity": "poc",
                },
            ],
        }]
    }))
    (state_dir / "ttp_mappings.json").write_text(json.dumps({
        "ttp_mappings": [
            {"attack_step_id": "S2", "similarity_score": 0.8, "technique_id": "T1"},
        ]
    }))
    (state_dir / "mitigations.json").write_text(json.dumps({
        "mitigations": [
            {"attack_step_id": "S2", "priority": 2, "mitigation_text": "patch"},
        ]
    }))
    (state_dir / "scanner_context.json").write_text(json.dumps({"tech_stack": "python"}))

    status = run_probability_stage(str(tmp_path), run_dir=str(tmp_path / "run-1"))
    assert "scored 2 steps" in status

    out = json.loads((state_dir / "attack_trees.json").read_text())
    steps = out["attack_trees"][0]["steps"]
    assert steps[0]["probability"] == 1.0
    assert steps[0]["reach_probability"] == 1.0
    assert "probability" in steps[1]
    assert 0.0 <= steps[1]["probability"] <= 1.0
    assert steps[1]["reach_probability"] == pytest.approx(steps[1]["probability"])  # fact parent


def test_run_probability_stage_idempotent(tmp_path: Path):
    state_dir = tmp_path / "run-2" / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "attack_trees.json").write_text(json.dumps({
        "attack_trees": [{
            "id": "AT1",
            "steps": [
                {"id": "S1", "parent_id": "", "category": "fact"},
                {
                    "id": "S2", "parent_id": "S1", "description": "x",
                    "skill_required": "med", "access_required": "none",
                    "detectability": "med", "exploit_maturity": "poc",
                },
            ],
        }]
    }))
    run_probability_stage(str(tmp_path), run_dir=str(tmp_path / "run-2"))
    first = json.loads((state_dir / "attack_trees.json").read_text())
    run_probability_stage(str(tmp_path), run_dir=str(tmp_path / "run-2"))
    second = json.loads((state_dir / "attack_trees.json").read_text())
    assert first == second


def test_run_probability_stage_missing_tree_file(tmp_path: Path):
    # Should not crash when the state file is absent.
    result = run_probability_stage(str(tmp_path), run_dir=str(tmp_path / "empty"))
    assert "no attack_trees" in result
