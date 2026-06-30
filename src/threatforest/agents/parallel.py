"""Parallel per-threat pipeline — fan-out tree/ttp/mitigation across threats.

Replaces the sequential tree → ttp → mitigation chain with parallel
execution: one sub-pipeline per threat, all running concurrently.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Optional

from threatforest.agents.scanner.agent import STATE_DIR, resolve_state_dir
from threatforest.agents.tracing_session import trace_attrs
from threatforest.workspace import LocalFilesystemWorkspace, Workspace

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


async def _run_ttp_review(
    ttp_candidates: list[dict],
    state_dir: Path,
    prefix: str,
    scanner_file: str,
    threat_idx: int,
    total_threats: int,
    run_dir: str | None = None,
) -> tuple[list[dict], list[Path]]:
    """Run the LLM-based TTP reviewer for one threat's candidates.

    Returns (ttp_mappings, temp_files_to_cleanup).
    """
    from strands import Agent, tool
    from strands.handlers import null_callback_handler
    from threatforest.modules.core.providers.provider_factory import create_model
    from threatforest.config import config
    from threatforest.tools.sandboxed_file import make_sandboxed_file_read, make_sandboxed_file_write

    _update_progress(total_threats, threat_idx, "🤖 TTP review")

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

    workspace = LocalFilesystemWorkspace(state_dir)
    summary_key = f"{prefix}_ttp_top1.json"
    workspace.write_json(summary_key, {"ttp_top1": summary})
    summary_file = state_dir / summary_key

    candidates_key = f"{prefix}_ttp_candidates.json"
    workspace.write_json(candidates_key, {"ttp_candidates": ttp_candidates})
    candidates_file = state_dir / candidates_key

    mappings_key = f"{prefix}_ttp_mappings.json"
    mappings_file = state_dir / mappings_key

    @tool
    def get_ttp_alternatives(attack_step_id: str) -> str:
        """Get top-5 alternative TTP candidates for a step that looks wrongly mapped.

        Args:
            attack_step_id: The ID of the attack step.
        """
        data = workspace.read_json(candidates_key)
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
        make_sandboxed_file_read([str(summary_file), scanner_file]),
        make_sandboxed_file_write([str(mappings_file)]),
        get_ttp_alternatives,
    ]

    ttp_agent = Agent(
        model=create_model(config, temperature=0),
        system_prompt=ttp_prompt,
        tools=ttp_tools,
        callback_handler=null_callback_handler(),
        trace_attributes=trace_attrs(f"ttp-T{threat_idx:03d}"),
    )

    await asyncio.to_thread(
        ttp_agent,
        "Read the top-1 TTP mappings. Review each one. If any look wrong, "
        "use get_ttp_alternatives. Write all final mappings to the state file.",
    )

    ttp_mappings = []
    if workspace.exists(mappings_key):
        try:
            raw = workspace.read_text(mappings_key).replace(",\n]", "\n]").replace(",]", "]")
            ttp_mappings = json.loads(raw).get("ttp_mappings", [])
        except (json.JSONDecodeError, OSError):
            pass

    return ttp_mappings, [summary_file, candidates_file, mappings_file]


async def _process_single_threat(
    threat: dict,
    threat_idx: int,
    total_threats: int,
    repo_path: str,
    scanner_context: dict,
    run_dir: str | None = None,
    frameworks: list[str] | None = None,
    scan_control: Any = None,
) -> dict:
    """Run tree → ttp_embed → mitigation for one threat.

    Returns a dict with keys: attack_trees, ttp_candidates, ttp_mappings, mitigations.
    Note: TTP reviewer step is currently disabled — embedding top-1 is used directly.
    """
    _empty_result = {"attack_trees": [], "ttp_candidates": [], "ttp_mappings": [], "mitigations": []}

    try:
        return await _process_single_threat_inner(
            threat, threat_idx, total_threats, repo_path, scanner_context,
            run_dir=run_dir, frameworks=frameworks, scan_control=scan_control,
        )
    except Exception:
        return _empty_result


async def _process_single_threat_inner(
    threat: dict,
    threat_idx: int,
    total_threats: int,
    repo_path: str,
    scanner_context: dict,
    run_dir: str | None = None,
    frameworks: list[str] | None = None,
    scan_control: Any = None,
) -> dict:
    """Inner implementation of _process_single_threat."""
    from threatforest.agents.tree.agent import create_tree_agent
    from threatforest.agents.mitigation.agent import create_mitigation_agent
    from threatforest.modules.workflow.ttc_mappings.matcher import TTCMatcher

    _empty_result = {"attack_trees": [], "ttp_candidates": [], "ttp_mappings": [], "mitigations": []}

    def _interrupted() -> bool:
        return scan_control is not None and scan_control.should_interrupt

    state_dir = resolve_state_dir(repo_path, run_dir)
    workspace = LocalFilesystemWorkspace(state_dir)
    prefix = f"t{threat_idx}"

    from threatforest.tools.sandboxed_file import make_sandboxed_file_read, make_sandboxed_file_write, make_store_mitigations
    from strands import Agent
    from strands.handlers import null_callback_handler
    from threatforest.modules.core.providers.provider_factory import create_model
    from threatforest.config import config

    scanner_file = str(state_dir / "scanner_context.json")
    single_threats_key = f"{prefix}_threats.json"
    single_threats_file = state_dir / single_threats_key
    tree_out_key = f"{prefix}_attack_trees.json"
    tree_out = state_dir / tree_out_key
    tree_out_str = str(tree_out)

    # --- Tree generation (skip if output already exists from a prior run) ---
    trees = []
    if workspace.exists(tree_out_key):
        try:
            trees = workspace.read_json(tree_out_key).get("attack_trees", [])
        except (json.JSONDecodeError, OSError):
            trees = []

    if not trees:
        if _interrupted():
            return _empty_result

        _update_progress(total_threats, threat_idx, "🌳 Building attack tree")

        workspace.write_json(single_threats_key, {"threats": [threat]})
        threats_file = str(single_threats_file)

        tree_prompt = (Path(__file__).parent / "tree" / "prompt.md").read_text()
        tree_prompt += (
            f"\n\n## Paths\n"
            f"- Scanner context: `{scanner_file}`\n"
            f"- Threats: `{threats_file}`\n"
            f"- Write output to: `{tree_out_str}`\n"
        )

        tree_tools = [
            make_sandboxed_file_read([scanner_file, threats_file, repo_path]),
            make_sandboxed_file_write([tree_out_str]),
        ]

        model = create_model(config, temperature=0)

        tree_hooks = []
        if scan_control is not None:
            from server.scan_control import ParallelInterruptHookProvider
            tree_hooks.append(ParallelInterruptHookProvider(scan_control))

        agent = Agent(
            model=model,
            system_prompt=tree_prompt,
            tools=tree_tools,
            callback_handler=null_callback_handler(),
            trace_attributes=trace_attrs(f"tree-T{threat_idx:03d}"),
            hooks=tree_hooks,
        )

        await asyncio.to_thread(
            agent, "Read the threat and scanner context. Generate an attack tree. Write to the output file."
        )

        if workspace.exists(tree_out_key):
            try:
                trees = workspace.read_json(tree_out_key).get("attack_trees", [])
            except (json.JSONDecodeError, OSError):
                pass

    if not trees:
        return _empty_result

    # Check for interrupt before proceeding to TTP embedding
    if _interrupted():
        return _empty_result

    # --- TTP embedding (no LLM, fast — always rerun) ---
    _update_progress(total_threats, threat_idx, "📐 TTP embedding")
    steps = []
    step_ids = []
    for tree in trees:
        for step in tree.get("steps", []):
            steps.append(step.get("description", ""))
            step_ids.append(step.get("id", ""))

    ttp_candidates = []
    if steps:
        from threatforest.config import config as _cfg
        matcher = TTCMatcher(min_similarity=_cfg.ttc_threshold, frameworks=frameworks)
        results = matcher.match_steps(steps, top_k=3)
        step_to_matches = {r["attack_step"]: r["matches"] for r in results}

        for sid, desc in zip(step_ids, steps):
            matches = step_to_matches.get(desc, [])
            top_k = [
                {"technique_id": m["technique_id"], "technique_name": m["name"],
                 "similarity_score": round(m["similarity"], 4), "rank": i + 1,
                 "framework": m.get("framework", "attack")}
                for i, m in enumerate(matches[:3])
            ]
            ttp_candidates.append({
                "attack_step_id": sid,
                "attack_step_description": desc,
                "top_k": top_k,
            })

    # Promote embedding top-1 directly (no LLM review)
    ttp_mappings = []
    for c in ttp_candidates:
        top1 = c["top_k"][0] if c.get("top_k") else {}
        if top1.get("technique_id"):
            ttp_mappings.append({
                "attack_step_id": c["attack_step_id"],
                "technique_id": top1["technique_id"],
                "technique_name": top1.get("technique_name", ""),
                "similarity_score": top1.get("similarity_score", 0),
                "framework": top1.get("framework", "attack"),
                "reviewer_overrode_top1": False,
                "reviewer_reasoning": "",
            })

    # Filter out techniques known to be irrelevant for cloud/serverless workloads
    _CLOUD_TTP_BLOCKLIST = {"T1014", "T1548.002", "T1088", "T1553.001"}
    ttp_mappings = [m for m in ttp_mappings if m["technique_id"] not in _CLOUD_TTP_BLOCKLIST]

    # Check for interrupt before proceeding to mitigation
    if _interrupted():
        return _empty_result

    # --- Mitigation (skip if output already exists from a prior run) ---
    mit_out_key = f"{prefix}_mitigations.json"
    mit_out = state_dir / mit_out_key
    mitigations = []

    if workspace.exists(mit_out_key):
        try:
            raw = workspace.read_text(mit_out_key).replace(",\n]", "\n]").replace(",]", "]")
            mitigations = json.loads(raw).get("mitigations", [])
        except (json.JSONDecodeError, OSError):
            mitigations = []

    if not mitigations:
        if _interrupted():
            return _empty_result

        _update_progress(total_threats, threat_idx, "🛡️ Defining relevant mitigations")
        mit_mappings_key = f"{prefix}_mitigations_input.json"
        mit_mappings_file = state_dir / mit_mappings_key
        workspace.write_json(mit_mappings_key, {"ttp_mappings": ttp_mappings})

        mit_prompt = (Path(__file__).parent / "mitigation" / "prompt.md").read_text()
        mit_prompt += (
            f"\n\n## Paths\n"
            f"- TTP mappings: `{mit_mappings_file}`\n"
            f"- Scanner context: `{scanner_file}`\n"
            f"- Attack trees: `{tree_out_str}`\n"
            f"- Output: call `store_mitigations` (path is preconfigured)\n"
        )

        mit_tools = [
            make_sandboxed_file_read([str(mit_mappings_file), scanner_file, tree_out_str, repo_path]),
            make_store_mitigations(str(mit_out)),
        ]

        mapped_step_ids = {m["attack_step_id"] for m in ttp_mappings if m.get("attack_step_id")}
        max_mit_attempts = 2

        for attempt in range(max_mit_attempts):
            if _interrupted():
                break

            workspace.delete(mit_out_key)

            mit_hooks = []
            if scan_control is not None:
                from server.scan_control import ParallelInterruptHookProvider
                mit_hooks.append(ParallelInterruptHookProvider(scan_control))

            mit_agent = Agent(
                model=create_model(config, temperature=0),
                system_prompt=mit_prompt,
                tools=mit_tools,
                callback_handler=null_callback_handler(),
                trace_attributes=trace_attrs(f"mitigation-T{threat_idx:03d}"),
                hooks=mit_hooks,
            )

            feedback = "" if attempt == 0 else (
                f" IMPORTANT: Your previous attempt was missing mitigations for some attack steps. "
                f"Make sure every technique in the TTP mappings file has a mitigation."
            )

            await asyncio.to_thread(
                mit_agent,
                f"Read the TTP mappings and scanner context. For each unique technique, synthesize an actionable mitigation with evidence. Call store_mitigations with the complete list.{feedback}"
            )

            mitigations = []
            if workspace.exists(mit_out_key):
                try:
                    raw = workspace.read_text(mit_out_key).replace(",\n]", "\n]").replace(",]", "]")
                    mitigations = json.loads(raw).get("mitigations", [])
                except (json.JSONDecodeError, OSError):
                    pass

            covered = set()
            for m in mitigations:
                sid = m.get("attack_step_id", "")
                if sid:
                    covered.add(sid)
                covered.update(m.get("also_applies_to", []))

            missing = mapped_step_ids - covered
            if not missing or not mitigations:
                break

        # Clean up transient input files only (keep output files for resume)
        for key in [single_threats_key, mit_mappings_key]:
            try:
                workspace.delete(key)
            except OSError:
                pass

    _mark_threat_complete(threat_idx)

    return {
        "attack_trees": trees,
        "ttp_candidates": ttp_candidates,
        "ttp_mappings": ttp_mappings,
        "mitigations": mitigations,
    }


def _renumber_trees(trees: list[dict], start_idx: int = 1) -> tuple[list[dict], dict[str, str]]:
    """Renumber attack tree IDs starting from start_idx.

    Returns (renumbered_trees, old_step_id_to_new_step_id_map).
    """
    renumbered = []
    id_map: dict[str, str] = {}

    for global_idx, tree in enumerate(trees, start=start_idx):
        old_tree_id = tree.get("id", f"AT{global_idx:03d}")
        new_tree_id = f"AT{global_idx:03d}"
        old_prefix = old_tree_id + "-"
        new_prefix = new_tree_id + "-"

        new_steps = []
        for step in tree.get("steps", []):
            old_sid = step.get("id", "")
            new_sid = new_prefix + old_sid[len(old_prefix):] if old_sid.startswith(old_prefix) else old_sid
            id_map[old_sid] = new_sid

            new_step = dict(step)
            new_step["id"] = new_sid
            old_parent = step.get("parent_id", "")
            if old_parent and old_parent.startswith(old_prefix):
                new_step["parent_id"] = new_prefix + old_parent[len(old_prefix):]
            new_steps.append(new_step)

        new_tree = dict(tree)
        new_tree["id"] = new_tree_id
        new_tree["steps"] = new_steps
        renumbered.append(new_tree)

    return renumbered, id_map


def _remap_step_ids(items: list[dict], id_map: dict[str, str]) -> list[dict]:
    """Remap attack_step_id and also_applies_to fields using the id_map."""
    remapped = []
    for item in items:
        new_item = dict(item)
        old_id = item.get("attack_step_id", "")
        if old_id in id_map:
            new_item["attack_step_id"] = id_map[old_id]
        also = item.get("also_applies_to", [])
        if also:
            new_item["also_applies_to"] = [id_map.get(s, s) for s in also]
        remapped.append(new_item)
    return remapped


def _consolidate_mitigations(mitigations: list[dict], ttp_mappings: list[dict]) -> list[dict]:
    """Merge per-technique duplicate mitigations across all threat pipelines.

    Groups by technique_id, keeps the highest-priority representative,
    and ensures every attack step that maps to the same technique is covered
    via also_applies_to (using ttp_mappings as the source of truth).
    """
    from collections import defaultdict

    # Build technique_id → all step IDs from ttp_mappings
    technique_to_steps: dict[str, set[str]] = defaultdict(set)
    for m in ttp_mappings:
        tid = m.get("technique_id", "")
        sid = m.get("attack_step_id", "")
        if tid and sid:
            technique_to_steps[tid].add(sid)

    by_technique: dict[str, list[dict]] = defaultdict(list)
    no_technique = []

    for m in mitigations:
        tid = m.get("technique_id", "")
        if tid:
            by_technique[tid].append(m)
        else:
            no_technique.append(m)

    consolidated = []
    for tid, group in by_technique.items():
        rep = min(group, key=lambda x: x.get("priority", 99))

        # Collect step IDs from mitigations themselves
        all_step_ids: set[str] = set()
        for m in group:
            sid = m.get("attack_step_id", "")
            if sid:
                all_step_ids.add(sid)
            all_step_ids.update(m.get("also_applies_to", []))

        # Add ALL steps that map to this technique (from ttp_mappings)
        all_step_ids.update(technique_to_steps.get(tid, set()))

        all_step_ids.discard(rep.get("attack_step_id", ""))
        all_step_ids.discard("")

        new_rep = dict(rep)
        new_rep["also_applies_to"] = sorted(all_step_ids)
        consolidated.append(new_rep)

    consolidated.extend(no_technique)

    return consolidated


def run_parallel_pipeline(repo_path: str, run_dir: str | None = None, frameworks: list[str] | None = None, scan_control: Any = None) -> str:
    """Fan out tree/ttp/mitigation across threats, merge results.

    Works both from a running event loop (server) and standalone (CLI).
    Returns the path to the merged mitigations file.

    Failed threats are retried up to ``max_parallel_retries`` times at the
    merge point.  Only the failed threats are re-run, not the entire batch.

    Args:
        repo_path: Path to the project repository.
        run_dir: Optional run directory for state files.
        frameworks: List of framework keys (e.g. ["attack", "atlas"]).
                    None means use all frameworks defined in config.
    """
    from threatforest.config import config as _cfg
    max_retries = _cfg.parallel_max_retries

    state_dir = resolve_state_dir(repo_path, run_dir)
    workspace = LocalFilesystemWorkspace(state_dir)

    threats_data = workspace.read_json("threats.json")
    scanner_context = workspace.read_json("scanner_context.json")
    threats = threats_data.get("threats", [])

    # Reset progress
    _progress.clear()

    if not threats:
        for name in ("attack_trees.json", "ttp_candidates.json", "ttp_mappings.json", "mitigations.json"):
            workspace.write_json(name, {name.replace(".json", ""): []})
        return str(state_dir / "mitigations.json")

    def _is_empty_result(r: Any) -> bool:
        """True when a threat produced no usable output (exception or empty)."""
        if isinstance(r, Exception):
            return True
        if not isinstance(r, dict):
            return True
        return (
            not r.get("attack_trees")
            and not r.get("mitigations")
        )

    def _run_threats(threat_items: list[tuple[int, dict]]) -> list[tuple[int, Any]]:
        """Run a batch of (index, threat) pairs and return (index, result) pairs."""
        total = len(threats)  # always show total against full threat count

        async def _run_batch():
            tasks = [
                _process_single_threat(
                    threat, idx, total, repo_path, scanner_context,
                    run_dir=run_dir, frameworks=frameworks, scan_control=scan_control,
                )
                for idx, threat in threat_items
            ]
            return await asyncio.gather(*tasks, return_exceptions=True)

        # Handle both: called from async context (server) or sync context (CLI)
        try:
            asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                batch_results = pool.submit(lambda: asyncio.run(_run_batch())).result()
        except RuntimeError:
            batch_results = asyncio.run(_run_batch())

        return list(zip([idx for idx, _ in threat_items], batch_results))

    # Initial run — all threats
    indexed_threats = list(enumerate(threats))
    indexed_results = _run_threats(indexed_threats)

    # Build results dict keyed by threat index
    results_by_idx: dict[int, Any] = {idx: r for idx, r in indexed_results}

    # Retry failed threats at the merge point.
    # Re-run ALL threats (not just failed ones) so each thread can leverage
    # its own skip-if-exists logic — threads that completed previously will
    # detect their output files and return immediately, while failed threads
    # re-run from the step that failed (partial output from earlier steps is
    # preserved and reused, just like the pause/resume flow).
    for retry_round in range(max_retries):
        # Check for interrupt before retrying
        if scan_control is not None and scan_control.should_interrupt:
            break

        has_failures = any(
            _is_empty_result(results_by_idx[idx])
            for idx in results_by_idx
        )
        if not has_failures:
            break

        retry_results = _run_threats(indexed_threats)
        for idx, r in retry_results:
            # Only update if the new result is better than what we had
            if _is_empty_result(results_by_idx.get(idx)) and not _is_empty_result(r):
                results_by_idx[idx] = r
            elif not _is_empty_result(r):
                results_by_idx[idx] = r

    # Collect ordered results for merging
    results = [results_by_idx[i] for i in range(len(threats))]

    # Merge results with per-result renumbering.
    # Each per-threat pipeline produces trees starting from AT001, so we must
    # renumber each result's trees separately to build a correct id_map before
    # remapping that result's candidates/mappings/mitigations.
    all_trees = []
    all_candidates = []
    all_mappings = []
    all_mitigations = []
    global_tree_idx = 0

    for r in results:
        if isinstance(r, Exception):
            continue
        r_trees = r.get("attack_trees", [])
        r_candidates = r.get("ttp_candidates", [])
        r_mappings = r.get("ttp_mappings", [])
        r_mitigations = r.get("mitigations", [])

        # Renumber this result's trees with a global offset
        renumbered, id_map = _renumber_trees(r_trees, start_idx=global_tree_idx + 1)
        global_tree_idx += len(renumbered)

        all_trees.extend(renumbered)
        all_candidates.extend(_remap_step_ids(r_candidates, id_map))
        all_mappings.extend(_remap_step_ids(r_mappings, id_map))
        all_mitigations.extend(_remap_step_ids(r_mitigations, id_map))

    # Consolidate duplicate mitigations (same technique across different threats)
    all_mitigations = _consolidate_mitigations(all_mitigations, all_mappings)

    workspace.write_json("attack_trees.json", {"attack_trees": all_trees})
    workspace.write_json("ttp_candidates.json", {"ttp_candidates": all_candidates})

    summary = []
    for c in all_candidates:
        top1 = c["top_k"][0] if c.get("top_k") else {}
        summary.append({
            "attack_step_id": c["attack_step_id"],
            "technique_id": top1.get("technique_id", ""),
            "technique_name": top1.get("technique_name", ""),
            "similarity_score": top1.get("similarity_score", 0),
        })
    workspace.write_json("ttp_top1_summary.json", {"ttp_top1": summary})

    workspace.write_json("ttp_mappings.json", {"ttp_mappings": all_mappings})
    workspace.write_json("mitigations.json", {"mitigations": all_mitigations})

    # Clean up per-threat output files only when the pipeline completed
    # without interruption.  If the scan was paused/stopped, keep them so
    # resumed runs can skip already-completed threats.
    interrupted = scan_control is not None and scan_control.should_interrupt
    if not interrupted:
        for i in range(len(threats)):
            for suffix in ("attack_trees", "mitigations", "threats", "mitigations_input"):
                try:
                    workspace.delete(f"t{i}_{suffix}.json")
                except OSError:
                    pass

    return str(state_dir / "mitigations.json")
