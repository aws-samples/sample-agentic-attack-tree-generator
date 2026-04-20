"""Probability pipeline stage.

Pure-Python: no LLM calls. Reads ``attack_trees.json``, ``ttp_mappings.json``,
``mitigations.json`` and ``scanner_context.json`` from the run's state
directory; computes per-step ``probability`` + ``probability_rationale`` and
the Markov ``reach_probability`` rollup; writes the augmented tree back to
``attack_trees.json`` in place.

Idempotent — re-running on the same state produces the same output.
"""

from __future__ import annotations

import json
from pathlib import Path

from threatforest.agents.scanner.agent import resolve_state_dir
from threatforest.agents.probability.prior import factor_prior
from threatforest.agents.probability.posterior import (
    compute_reach,
    detect_tech_stack_mismatch,
    update_posterior,
)


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        # Tolerate trailing commas the mitigation state sometimes ends up with.
        raw = path.read_text().replace(",\n]", "\n]").replace(",]", "]")
        return json.loads(raw) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def _index_by_step(entries: list[dict], id_key: str = "attack_step_id") -> dict[str, dict]:
    out: dict[str, dict] = {}
    for entry in entries:
        sid = entry.get(id_key, "")
        if sid:
            out[sid] = entry
        for also in entry.get("also_applies_to", []) or []:
            if also and also not in out:
                out[also] = entry
    return out


def compute_probabilities(
    trees: list[dict],
    ttp_by_step: dict[str, dict],
    mitigations_by_step: dict[str, dict],
    tech_stack: str = "",
) -> None:
    """Mutate *trees* in place, setting probability + rationale + reach."""
    for tree in trees:
        steps = tree.get("steps", [])
        for step in steps:
            if step.get("category") == "fact":
                # Fact node is the precondition: reach = 1.0, local p = 1.0.
                step["probability"] = 1.0
                step["probability_rationale"] = "fact node (attacker precondition)"
                continue

            prior, prior_rationale = factor_prior(step)

            ttp = ttp_by_step.get(step.get("id", ""), {})
            sim = ttp.get("similarity_score")
            mit = mitigations_by_step.get(step.get("id", ""), {})
            mit_priority = mit.get("priority")

            mismatch = detect_tech_stack_mismatch(step.get("description", ""), tech_stack)

            posterior, post_rationale = update_posterior(
                prior,
                ttp_similarity=float(sim) if isinstance(sim, (int, float)) else None,
                mitigation_priority=int(mit_priority) if isinstance(mit_priority, int) else None,
                feasibility_note=step.get("feasibility_note", ""),
                tech_stack_mismatch=mismatch,
            )

            step["probability"] = round(posterior, 4)
            step["probability_rationale"] = f"{prior_rationale} → posterior: {post_rationale}"

        reach_map = compute_reach(steps)
        for step in steps:
            sid = step.get("id", "")
            step["reach_probability"] = round(reach_map.get(sid, 0.0), 4)


def run_probability_stage(repo_path: str, run_dir: str | None = None) -> str:
    """GraphNode entry point.

    Loads state, computes probabilities + reach, writes back in place.
    Returns a short status string for the orchestrator logs.
    """
    state_dir = resolve_state_dir(repo_path, run_dir)
    tree_path = state_dir / "attack_trees.json"
    if not tree_path.exists():
        return "probability: no attack_trees.json to process"

    tree_blob = _load_json(tree_path)
    trees = tree_blob.get("attack_trees", [])
    if not trees:
        return "probability: no trees to process"

    ttp_blob = _load_json(state_dir / "ttp_mappings.json")
    mit_blob = _load_json(state_dir / "mitigations.json")
    scanner_blob = _load_json(state_dir / "scanner_context.json")

    ttp_by_step = _index_by_step(ttp_blob.get("ttp_mappings", []), id_key="attack_step_id")
    mitigations_by_step = _index_by_step(mit_blob.get("mitigations", []), id_key="attack_step_id")
    tech_stack = (scanner_blob.get("tech_stack") or "") if isinstance(scanner_blob, dict) else ""

    compute_probabilities(trees, ttp_by_step, mitigations_by_step, tech_stack=tech_stack)

    tree_blob["attack_trees"] = trees
    tree_path.write_text(json.dumps(tree_blob, indent=2))

    total_steps = sum(len(t.get("steps", [])) for t in trees)
    return f"probability: scored {total_steps} steps across {len(trees)} trees"
