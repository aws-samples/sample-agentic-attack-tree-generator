"""TTP Embedding Model — vector search against MITRE ATT&CK techniques.

Not an LLM. Uses the existing TTCMatcher to embed attack steps and
find top-K technique candidates via cosine similarity.
"""

import json
from pathlib import Path

from threatforest.agents.scanner.agent import STATE_DIR


STATE_FILE = "ttp_candidates.json"


def run_ttp_embedding(repo_path: str, top_k: int = 3) -> str:
    """Run embedding-based TTP matching and write candidates to state file.

    Returns the state file path.
    """
    state_dir = Path(repo_path) / STATE_DIR
    trees_file = state_dir / "attack_trees.json"
    out_file = state_dir / STATE_FILE

    # Load attack steps from trees
    trees_data = json.loads(trees_file.read_text())
    steps = []
    step_ids = []
    for tree in trees_data.get("attack_trees", []):
        for step in tree.get("steps", []):
            steps.append(step.get("description", ""))
            step_ids.append(step.get("id", ""))

    if not steps:
        out_file.write_text(json.dumps({"ttp_candidates": []}))
        return str(out_file)

    # Use existing matcher infrastructure
    from threatforest.modules.workflow.ttc_mappings.matcher import TTCMatcher

    from threatforest.config import config as _cfg
    matcher = TTCMatcher(min_similarity=_cfg.ttc_threshold)
    results = matcher.match_steps(steps, top_k=top_k)

    # Build candidates keyed by step
    step_to_result = {}
    for r in results:
        step_text = r["attack_step"]
        step_to_result[step_text] = r["matches"]

    candidates = []
    for sid, desc in zip(step_ids, steps):
        matches = step_to_result.get(desc, [])
        candidates.append({
            "attack_step_id": sid,
            "attack_step_description": desc,
            "top_k": [
                {
                    "technique_id": m["technique_id"],
                    "technique_name": m["name"],
                    "similarity_score": round(m["similarity"], 4),
                    "rank": i + 1,
                }
                for i, m in enumerate(matches[:top_k])
            ],
        })

    out_file.write_text(json.dumps({"ttp_candidates": candidates}, indent=2))

    # Write slim top-1 summary for the reviewer
    summary = []
    for c in candidates:
        top1 = c["top_k"][0] if c.get("top_k") else {}
        summary.append({
            "attack_step_id": c["attack_step_id"],
            "attack_step_description": c.get("attack_step_description", ""),
            "technique_id": top1.get("technique_id", ""),
            "technique_name": top1.get("technique_name", ""),
            "similarity_score": top1.get("similarity_score", 0),
        })
    (state_dir / "ttp_top1_summary.json").write_text(
        json.dumps({"ttp_top1": summary}, indent=2)
    )

    return str(out_file)
