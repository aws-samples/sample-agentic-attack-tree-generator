"""Parallel per-threat pipeline — fan-out tree/ttp/mitigation across threats.

Replaces the sequential tree → ttp → mitigation chain with parallel
execution: one sub-pipeline per threat, all running concurrently.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Optional

from threatforest.agents.scanner.agent import STATE_DIR

import threading

# Shared progress state — updated by worker threads, read by UI
_progress: dict[str, Any] = {}
_progress_lock = threading.Lock()


def get_parallel_progress() -> dict[str, Any]:
    """Read current parallel pipeline progress (called by graph UI)."""
    with _progress_lock:
        return dict(_progress)


def _update_progress(total_threats: int, threat_idx: int, stage: str, detail: str = ""):
    with _progress_lock:
        _progress["total_threats"] = total_threats
        _progress["threat_idx"] = threat_idx
        _progress["stage"] = stage
        _progress["detail"] = detail
        # Track per-threat status
        if "threat_status" not in _progress:
            _progress["threat_status"] = {}
        _progress["threat_status"][threat_idx] = {"stage": stage, "detail": detail}
        completed = _progress.get("completed_threats", set())
        _progress["completed_count"] = len(completed)


def _mark_threat_complete(threat_idx: int):
    with _progress_lock:
        completed = _progress.get("completed_threats", set())
        completed.add(threat_idx)
        _progress["completed_threats"] = completed
        _progress["completed_count"] = len(completed)


async def _process_single_threat(
    threat: dict,
    threat_idx: int,
    total_threats: int,
    repo_path: str,
    scanner_context: dict,
) -> dict:
    """Run tree → ttp_embed → ttp_review → mitigation for one threat.

    Returns a dict with keys: attack_trees, ttp_candidates, ttp_mappings, mitigations.
    """
    from threatforest.agents.tree.agent import create_tree_agent
    from threatforest.agents.ttp.reviewer import create_ttp_reviewer
    from threatforest.agents.mitigation.agent import create_mitigation_agent
    from threatforest.modules.workflow.ttc_mappings.matcher import TTCMatcher

    state_dir = Path(repo_path) / STATE_DIR
    prefix = f"t{threat_idx}"

    # --- Tree generation ---
    _update_progress(total_threats, threat_idx, "🌳 Tree", threat.get("name", threat.get("description", ""))[:50])

    # Write single-threat input for this sub-pipeline
    single_threats_file = state_dir / f"{prefix}_threats.json"
    single_threats_file.write_text(json.dumps({"threats": [threat]}))

    tree_agent = create_tree_agent(repo_path)
    tree_out = state_dir / f"{prefix}_attack_trees.json"

    # Patch the agent's write path to the per-threat file
    from threatforest.tools.sandboxed_file import make_sandboxed_file_read, make_sandboxed_file_write
    from strands import Agent
    from strands.handlers import null_callback_handler
    from threatforest.modules.core.providers.provider_factory import create_model
    from threatforest.config import config

    # Create a tree agent scoped to this single threat
    scanner_file = str(state_dir / "scanner_context.json")
    threats_file = str(single_threats_file)
    tree_out_str = str(tree_out)

    tree_prompt = (Path(__file__).parent / "tree" / "prompt.md").read_text()
    tree_prompt += (
        f"\n\n## Paths\n"
        f"- Scanner context: `{scanner_file}`\n"
        f"- Threats: `{threats_file}`\n"
        f"- Write output to: `{tree_out_str}`\n"
    )

    tree_tools = [
        make_sandboxed_file_read([scanner_file, threats_file]),
        make_sandboxed_file_write([tree_out_str]),
    ]

    model = create_model(config, temperature=0)
    agent = Agent(
        model=model,
        system_prompt=tree_prompt,
        tools=tree_tools,
        callback_handler=null_callback_handler(),
    )

    # Run tree generation (sync agent call in async context via thread)
    await asyncio.to_thread(
        agent, "Read the threat and scanner context. Generate an attack tree. Write to the output file."
    )

    # Parse tree output
    trees = []
    if tree_out.exists():
        try:
            trees = json.loads(tree_out.read_text()).get("attack_trees", [])
        except (json.JSONDecodeError, OSError):
            pass

    if not trees:
        return {"attack_trees": [], "ttp_candidates": [], "ttp_mappings": [], "mitigations": []}

    # --- TTP embedding (no LLM) ---
    _update_progress(total_threats, threat_idx, "📐 TTP Embed")
    steps = []
    step_ids = []
    for tree in trees:
        for step in tree.get("steps", []):
            steps.append(step.get("description", ""))
            step_ids.append(step.get("id", ""))

    ttp_candidates = []
    if steps:
        matcher = TTCMatcher(min_similarity=0.2)
        results = matcher.match_steps(steps, top_k=3)
        step_to_matches = {r["attack_step"]: r["matches"] for r in results}

        for sid, desc in zip(step_ids, steps):
            matches = step_to_matches.get(desc, [])
            top_k = [
                {"technique_id": m["technique_id"], "technique_name": m["name"],
                 "similarity_score": round(m["similarity"], 4), "rank": i + 1}
                for i, m in enumerate(matches[:3])
            ]
            ttp_candidates.append({
                "attack_step_id": sid,
                "attack_step_description": desc,
                "top_k": top_k,
            })

    # --- TTP review (LLM) ---
    _update_progress(total_threats, threat_idx, "🤖 TTP Review")
    # Write top-1 summary for reviewer
    summary = []
    for c in ttp_candidates:
        top1 = c["top_k"][0] if c.get("top_k") else {}
        summary.append({
            "attack_step_id": c["attack_step_id"],
            "attack_step_description": c.get("attack_step_description", ""),
            "technique_id": top1.get("technique_id", ""),
            "technique_name": top1.get("technique_name", ""),
            "similarity_score": top1.get("similarity_score", 0),
        })

    summary_file = state_dir / f"{prefix}_ttp_top1.json"
    summary_file.write_text(json.dumps({"ttp_top1": summary}, indent=2))

    candidates_file = state_dir / f"{prefix}_ttp_candidates.json"
    candidates_file.write_text(json.dumps({"ttp_candidates": ttp_candidates}, indent=2))

    mappings_file = state_dir / f"{prefix}_ttp_mappings.json"

    # Build alternatives tool for this threat's candidates
    from strands import tool

    @tool
    def get_ttp_alternatives(attack_step_id: str) -> str:
        """Get top-5 alternative TTP candidates for a step that looks wrongly mapped.

        Args:
            attack_step_id: The ID of the attack step.
        """
        data = json.loads(candidates_file.read_text())
        for c in data.get("ttp_candidates", []):
            if c["attack_step_id"] == attack_step_id:
                return json.dumps(c["top_k"], indent=2)
        return f"No candidates found for {attack_step_id}"

    ttp_prompt = (Path(__file__).parent / "ttp" / "prompt.md").read_text()
    ttp_prompt += (
        f"\n\n## Paths\n"
        f"- TTP top-1 mappings: `{summary_file}`\n"
        f"- Write output to: `{mappings_file}`\n"
    )

    ttp_tools = [
        make_sandboxed_file_read([str(summary_file)]),
        make_sandboxed_file_write([str(mappings_file)]),
        get_ttp_alternatives,
    ]

    ttp_agent = Agent(
        model=create_model(config, temperature=0),
        system_prompt=ttp_prompt,
        tools=ttp_tools,
        callback_handler=null_callback_handler(),
    )

    await asyncio.to_thread(
        ttp_agent,
        "Read the top-1 TTP mappings. Review each one. If any look wrong, use get_ttp_alternatives. Write all final mappings to the state file."
    )

    ttp_mappings = []
    if mappings_file.exists():
        try:
            raw = mappings_file.read_text().replace(",\n]", "\n]").replace(",]", "]")
            ttp_mappings = json.loads(raw).get("ttp_mappings", [])
        except (json.JSONDecodeError, OSError):
            pass

    # --- Mitigation (LLM) ---
    _update_progress(total_threats, threat_idx, "🛡️ Mitigation")
    mit_mappings_file = state_dir / f"{prefix}_mitigations_input.json"
    mit_mappings_file.write_text(json.dumps({"ttp_mappings": ttp_mappings}, indent=2))

    mit_out = state_dir / f"{prefix}_mitigations.json"

    mit_prompt = (Path(__file__).parent / "mitigation" / "prompt.md").read_text()
    mit_prompt += (
        f"\n\n## Paths\n"
        f"- TTP mappings: `{mit_mappings_file}`\n"
        f"- Scanner context: `{scanner_file}`\n"
        f"- Attack trees: `{tree_out_str}`\n"
        f"- Write output to: `{mit_out}`\n"
    )

    mit_tools = [
        make_sandboxed_file_read([str(mit_mappings_file), scanner_file, tree_out_str]),
        make_sandboxed_file_write([str(mit_out)]),
    ]

    mit_agent = Agent(
        model=create_model(config, temperature=0),
        system_prompt=mit_prompt,
        tools=mit_tools,
        callback_handler=null_callback_handler(),
    )

    await asyncio.to_thread(
        mit_agent,
        "Read the TTP mappings and scanner context. For each unique technique, write an actionable mitigation with evidence. Write to the state file."
    )

    mitigations = []
    if mit_out.exists():
        try:
            raw = mit_out.read_text().replace(",\n]", "\n]").replace(",]", "]")
            mitigations = json.loads(raw).get("mitigations", [])
        except (json.JSONDecodeError, OSError):
            pass

    # Cleanup temp files
    for f in [single_threats_file, summary_file, candidates_file, mappings_file, mit_mappings_file, mit_out, tree_out]:
        try:
            f.unlink(missing_ok=True)
        except OSError:
            pass

    _mark_threat_complete(threat_idx)

    return {
        "attack_trees": trees,
        "ttp_candidates": ttp_candidates,
        "ttp_mappings": ttp_mappings,
        "mitigations": mitigations,
    }


def run_parallel_pipeline(repo_path: str) -> str:
    """Fan out tree/ttp/mitigation across threats, merge results.

    Works both from a running event loop (server) and standalone (CLI).
    Returns the path to the merged mitigations file.
    """
    state_dir = Path(repo_path) / STATE_DIR
    threats_file = state_dir / "threats.json"
    scanner_file = state_dir / "scanner_context.json"

    threats_data = json.loads(threats_file.read_text())
    scanner_context = json.loads(scanner_file.read_text())
    threats = threats_data.get("threats", [])

    # Reset progress
    _progress.clear()

    if not threats:
        for name in ("attack_trees.json", "ttp_candidates.json", "ttp_mappings.json", "mitigations.json"):
            (state_dir / name).write_text(json.dumps({name.replace(".json", ""): []}))
        return str(state_dir / "mitigations.json")

    async def _run_all():
        tasks = [
            _process_single_threat(threat, i, len(threats), repo_path, scanner_context)
            for i, threat in enumerate(threats)
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)

    # Handle both: called from async context (server) or sync context (CLI)
    try:
        asyncio.get_running_loop()
        # Already in an event loop — run in a new thread with its own loop
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            results = pool.submit(lambda: asyncio.run(_run_all())).result()
    except RuntimeError:
        # No running loop — safe to use asyncio.run directly
        results = asyncio.run(_run_all())

    # Merge results
    all_trees = []
    all_candidates = []
    all_mappings = []
    all_mitigations = []

    for r in results:
        if isinstance(r, Exception):
            continue
        all_trees.extend(r.get("attack_trees", []))
        all_candidates.extend(r.get("ttp_candidates", []))
        all_mappings.extend(r.get("ttp_mappings", []))
        all_mitigations.extend(r.get("mitigations", []))

    (state_dir / "attack_trees.json").write_text(json.dumps({"attack_trees": all_trees}, indent=2))
    (state_dir / "ttp_candidates.json").write_text(json.dumps({"ttp_candidates": all_candidates}, indent=2))

    summary = []
    for c in all_candidates:
        top1 = c["top_k"][0] if c.get("top_k") else {}
        summary.append({
            "attack_step_id": c["attack_step_id"],
            "technique_id": top1.get("technique_id", ""),
            "technique_name": top1.get("technique_name", ""),
            "similarity_score": top1.get("similarity_score", 0),
        })
    (state_dir / "ttp_top1_summary.json").write_text(json.dumps({"ttp_top1": summary}, indent=2))

    (state_dir / "ttp_mappings.json").write_text(json.dumps({"ttp_mappings": all_mappings}, indent=2))
    (state_dir / "mitigations.json").write_text(json.dumps({"mitigations": all_mitigations}, indent=2))

    return str(state_dir / "mitigations.json")
