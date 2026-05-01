"""Executor that bridges RunManager to the ThreatForest graph pipeline.

Reads configuration from ``.threatforest/config.yaml``, syncs it to the
engine's expected location, and runs the v2 graph pipeline.  Progress
events from the graph stream are forwarded to the RunManager callback.
"""

from __future__ import annotations

import asyncio
import json as _json_module
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import yaml

from server.applications import (
    ApplicationNotFoundError,
    get_repository as get_app_repository,
)
from server.models import Application, RunConfig
from server.run_manager import OrchestratorExecutor, ProgressEvent

if TYPE_CHECKING:
    from server.scan_control import ScanControl


def _save_pause_state(
    run_dir: Path,
    completed_nodes: list[str],
    intent: str,
    config: RunConfig,
) -> None:
    """Persist pause/stop state so the run can be resumed later.

    Writes ``pause_state.json`` into *run_dir* with the set of graph nodes
    that completed successfully and the original ``RunConfig`` fields needed
    to reconstruct the run.
    """
    pause_data = {
        "intent": intent,
        "paused_at": datetime.now(timezone.utc).isoformat(),
        "completed_nodes": completed_nodes,
        "config": {
            "project_path": config.project_path,
            "threat_source": config.threat_source,
            "threat_file_path": config.threat_file_path,
            "app_id": config.app_id,
        },
    }
    (run_dir / "pause_state.json").write_text(
        _json_module.dumps(pause_data, indent=2), encoding="utf-8"
    )


_otel_initialized = False


def _setup_langfuse_otel() -> None:
    """Configure Strands OTEL exporter to send traces to Langfuse."""
    global _otel_initialized
    import os
    import base64

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    enabled = os.environ.get("LANGFUSE_ENABLED", "false").lower() == "true"
    host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")

    if not enabled or not public_key or not secret_key:
        return

    # Set OTEL env vars for Langfuse
    auth = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = f"{host}/api/public/otel"
    os.environ["OTEL_EXPORTER_OTLP_HEADERS"] = f"Authorization=Basic {auth}"

    if _otel_initialized:
        return
    _otel_initialized = True

    try:
        from strands.telemetry import StrandsTelemetry
        StrandsTelemetry().setup_otlp_exporter()
    except ImportError:
        pass


def _load_config_yaml(workspace_dir: Path) -> dict[str, Any]:
    config_path = workspace_dir / ".threatforest" / "config.yaml"
    if not config_path.is_file():
        raise RuntimeError(
            "ThreatForest configuration not found. "
            "Please configure ThreatForest first via the Configure page."
        )
    return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}


def _extract_model_settings(raw: dict[str, Any]) -> tuple[str, str | None]:
    provider_keys = ["bedrock", "anthropic", "openai", "google_gemini", "ollama"]
    for key in provider_keys:
        section = raw.get(key)
        if isinstance(section, dict) and section.get("model_id"):
            return section["model_id"], section.get("aws_profile")
    raise RuntimeError(
        "No model_id configured in .threatforest/config.yaml. "
        "Please configure ThreatForest first via the Configure page."
    )


def _sync_config_to_engine(workspace_dir: Path, engine_root: Path) -> None:
    import shutil
    src_dir = workspace_dir / ".threatforest"
    dst_dir = engine_root / ".threatforest"
    if not src_dir.is_dir():
        return
    if src_dir.resolve() == dst_dir.resolve():
        return
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in ("config.yaml", ".env"):
        src_file = src_dir / name
        if src_file.is_file():
            shutil.copy2(str(src_file), str(dst_dir / name))


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _seed_scanner_context(run_dir: Path, app: Application) -> None:
    """Pre-populate ``<run_dir>/state/scanner_context.json`` from business context.

    The scanner agent is the first node in the graph and normally writes a
    fresh file. When the run is tied to a persistent ``Application``, we seed
    the file before the scanner starts so every downstream agent (which reads
    the same file via their sandboxed file tools) sees user-authoritative
    business context without any separate side-channel.

    The seed contains both:

    - A nested ``business_context`` block — the authoritative record of what
      the user entered.
    - Top-level ``compliance_requirements``, ``data_sensitivity`` and
      ``main_cia_risk`` — mirrors of the fields the scanner / interviewer
      already enrich, so existing fill-if-not-set and unique-append logic
      naturally preserves the user's values. The threat agent and scanner
      review UI read them from the top level.

    Leaves an existing file untouched (resume flows re-enter with state already
    written from the previous attempt — we never clobber it).
    """
    state_dir = run_dir / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "scanner_context.json"
    if state_file.is_file():
        return

    bc = app.business_context
    seed: dict[str, Any] = {
        "business_context": {
            "description": bc.description,
            "regulatory_frameworks": list(bc.regulatory_frameworks),
            "data_sensitivity": bc.data_sensitivity,
            "main_cia_risk": bc.main_cia_risk,
        },
        # Mirrored into top-level fields that the scanner + interviewer
        # already understand, so downstream enrichment logic is zero-change.
        "compliance_requirements": list(bc.regulatory_frameworks),
        "data_sensitivity": bc.data_sensitivity,
        "main_cia_risk": bc.main_cia_risk,
    }
    state_file.write_text(
        _json_module.dumps(seed, indent=2, sort_keys=True),
        encoding="utf-8",
    )


# Map graph node IDs to UI stage names.
# The parallel_pipeline node now maps to a single "Parallel Analysis" stage
# instead of the old 3 separate stages (Attack Tree Generation, TTP Enrichment,
# Mitigation Mapping) which were misleading since they all run concurrently.
NODE_LABELS = {
    "scanner": "Repository Analysis",
    "scanner_verifier": "Repository Analysis",
    "scanner_review": "Repository Analysis",
    "interviewer": "Context Validation",
    "threat": "Threat Generation",
    "threat_verifier": "Threat Generation",
    "threat_review": "Threat Review",
    "parallel_pipeline": "Parallel Analysis",
    "parallel_verifier": "Parallel Analysis",
    "probability": "Probability Scoring",
    "report": "Dashboard Generation",
    "report_verifier": "Dashboard Generation",
}

# Expected tool calls per node (for progress estimation)
NODE_TOOL_ESTIMATES = {
    "scanner": 10,
    "scanner_verifier": 1,
    "threat": 5,
    "threat_verifier": 1,
    "report": 6,
    "report_verifier": 1,
}

# Human-readable descriptions for tool names (generic fallback)
TOOL_DESCRIPTIONS = {
    "structural_analyzer": "📂 Scanning project structure",
    "sandboxed_file_read": "📄 Reading project files",
    "sandboxed_file_write": "💾 Writing analysis results",
}

# Node-specific tool descriptions for more informative progress messages
NODE_TOOL_DESCRIPTIONS = {
    "scanner": {
        "sandboxed_file_read": "📄 Reading project files",
        "sandboxed_file_write": "💾 Saving scanner analysis",
        "structural_analyzer": "📂 Scanning project structure",
    },
    "threat": {
        "sandboxed_file_read": "📖 Reading scanner context for threat analysis",
        "sandboxed_file_write": "💾 Writing threat statements",
        "structural_analyzer": "🔍 Deep-scanning project for threat surface",
    },
    "report": {
        "sandboxed_file_read": "📄 Reading analysis results",
        "sandboxed_file_write": "📝 Generating dashboard report",
    },
}


def _get_stage_summary(project_path: str, node_id: str, run_dir: str | None = None) -> dict | None:
    """Read state files and return a summary dict for the completed node."""
    import json as _json
    if run_dir:
        sd = Path(run_dir) / "state"
    else:
        sd = Path(project_path) / ".threatforest" / "state"
    try:
        if node_id == "scanner_review":
            d = _json.loads((sd / "scanner_context.json").read_text())
            return {
                "message": f"Analyzed {len(d.get('files_analyzed', []))} files",
                "findings": [
                    f"☁️ Cloud: {d.get('cloud_provider', 'unknown').upper()}",
                    f"🔧 Stack: {d.get('tech_stack', '')}",
                    f"📦 Services: {', '.join(d.get('services', []))}",
                    f"🔐 Auth: {', '.join(d.get('auth_mechanisms', [])) or 'none detected'}",
                ],
            }
        if node_id == "interviewer":
            d = _json.loads((sd / "scanner_context.json").read_text())
            confidence = d.get("interviewer_confidence", "skipped")
            summary = d.get("interviewer_summary", "")
            findings = [f"Confidence: {confidence}"]
            if summary:
                findings.append(summary)
            return {"message": f"Context validation: {confidence} confidence", "findings": findings}
        if node_id in ("scanner", "scanner_verifier"):
            d = _json.loads((sd / "scanner_context.json").read_text())
            return {
                "message": f"Analyzed {len(d.get('files_analyzed', []))} files",
                "findings": [
                    f"☁️ Cloud: {d.get('cloud_provider', 'unknown').upper()}",
                    f"🔧 Stack: {d.get('tech_stack', '')}",
                    f"📦 Services: {', '.join(d.get('services', []))}",
                    f"🔐 Auth: {', '.join(d.get('auth_mechanisms', [])) or 'none detected'}",
                ],
            }
        elif node_id in ("threat", "threat_verifier"):
            d = _json.loads((sd / "threats.json").read_text())
            threats = d.get("threats", [])
            findings = [f"{len(threats)} threats identified"]
            for t in threats:
                sev = t.get("priority") or t.get("severity") or "medium"
                title = t.get("title", t.get("name", t.get("description", "")))
                findings.append(f"  [{sev.upper()}] {title}")
            return {"message": f"{len(threats)} threats identified", "findings": findings}
        elif node_id == "threat_review":
            d = _json.loads((sd / "threats.json").read_text())
            threats = d.get("threats", [])
            findings = [f"{len(threats)} threats after review"]
            for t in threats:
                sev = t.get("priority") or t.get("severity") or "medium"
                title = t.get("title", t.get("name", t.get("description", "")))
                findings.append(f"  [{sev.upper()}] {title}")
            return {"message": f"Threat review complete · {len(threats)} threats", "findings": findings}
        elif node_id in ("parallel_pipeline", "parallel_verifier"):
            trees = _json.loads((sd / "attack_trees.json").read_text()).get("attack_trees", [])
            raw_m = (sd / "ttp_mappings.json").read_text().replace(",\n]", "\n]").replace(",]", "]")
            mappings = _json.loads(raw_m).get("ttp_mappings", [])
            raw_mit = (sd / "mitigations.json").read_text().replace(",\n]", "\n]").replace(",]", "]")
            mits = _json.loads(raw_mit).get("mitigations", [])
            total_steps = sum(len(t.get("steps", [])) for t in trees)
            techniques = {m.get("technique_id") for m in mappings if m.get("technique_id")}
            return {
                "message": f"{len(trees)} trees · {total_steps} steps · {len(mits)} mitigations",
                "findings": [
                    f"🌳 {len(trees)} attack trees with {total_steps} total steps",
                    f"🎯 {len(mappings)} TTP mappings across {len(techniques)} unique techniques",
                    f"🛡️ {len(mits)} mitigations generated",
                ],
            }
        elif node_id == "probability":
            trees = _json.loads((sd / "attack_trees.json").read_text()).get("attack_trees", [])
            all_steps = [s for t in trees for s in t.get("steps", [])]
            scored = [s for s in all_steps if s.get("category") != "fact"]
            high = [s for s in scored if s.get("reach_probability", 0) >= 0.5]
            avg = (sum(s.get("reach_probability", 0) for s in scored) / len(scored)) if scored else 0
            return {
                "message": f"Scored {len(scored)} steps · avg reach {avg:.2f}",
                "findings": [
                    f"📊 {len(scored)} non-fact steps scored",
                    f"🔥 {len(high)} steps with reach probability ≥ 0.5",
                    f"📈 Average reach probability: {avg:.2f}",
                ],
            }
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        pass
    return None


def create_orchestrator_executor(workspace_dir: Path) -> OrchestratorExecutor:
    """Return an executor that runs the ThreatForest graph pipeline."""
    threatforest_src = workspace_dir / "src"

    def executor(
        config: RunConfig,
        progress_callback: Callable[[ProgressEvent], None],
        scan_control: "ScanControl | None" = None,
        interaction_fn=None,
    ) -> dict[str, str]:
        import os

        # 1. sys.path
        src_str = str(threatforest_src)
        if src_str not in sys.path:
            sys.path.insert(0, src_str)

        # 2. Config
        raw = _load_config_yaml(workspace_dir)
        _, aws_profile = _extract_model_settings(raw)
        if aws_profile:
            os.environ["AWS_PROFILE"] = aws_profile

        # 3. Sync config to engine root
        try:
            import threatforest.config as _tf_cfg_mod
            actual_engine_root = Path(_tf_cfg_mod.__file__).parent.parent.parent
        except (ImportError, AttributeError):
            actual_engine_root = workspace_dir
        _sync_config_to_engine(workspace_dir, actual_engine_root)

        # 3a. Load .env so Langfuse env vars are available to the pipeline
        from dotenv import load_dotenv as _load_dotenv
        for env_path in (
            actual_engine_root / ".threatforest" / ".env",
            workspace_dir / ".threatforest" / ".env",
        ):
            if env_path.is_file():
                _load_dotenv(dotenv_path=str(env_path), override=True)

        # 3b. Reset Config singleton
        try:
            from threatforest.config import Config as _TFConfig
            _TFConfig._instance = None
            _TFConfig._config = None
            _TFConfig._config_path = None
        except (ImportError, AttributeError):
            pass

        # 3c. Reset TracingManager singleton so it picks up fresh env vars
        try:
            from threatforest.tracing.manager import TracingManager as _TM
            _TM.reset()
        except (ImportError, AttributeError):
            pass

        # 3d. Set up Langfuse OTEL tracing for Strands agents
        from threatforest.agents.tracing_session import setup_langfuse_otel, init_session
        setup_langfuse_otel()

        # 3e. Initialize tracing session so all agents share the same session ID
        session_id = init_session()

        # 4. Run the graph pipeline with progress streaming
        from threatforest.agents.graph import build_graph
        from strands.multiagent.base import Status
        from server.registry import create_run_directory, slugify

        project_path = str(Path(config.project_path).expanduser().resolve())
        if not Path(project_path).is_dir():
            # Try resolving relative to workspace
            candidate = workspace_dir / config.project_path
            if candidate.is_dir():
                project_path = str(candidate.resolve())

        # 4a. Fail-early input validation — catch problems before burning tokens
        from threatforest.modules.core.providers.provider_factory import create_model
        from threatforest.config import config as tf_config

        # Validate model provider is configured (raises ValueError if not)
        create_model(tf_config, temperature=0)

        # Validate project has analyzable files
        from threatforest.agents.scanner.agent import _count_source_files
        if _count_source_files(project_path) == 0:
            raise ValueError(
                f"No analyzable files found in {project_path}. "
                "The project directory must contain at least one file to analyze "
                "(source code, documentation, config, etc.)."
            )

        # Validate threat file exists when threat_source is "file"
        if config.threat_source == "file" and config.threat_file_path:
            threat_file = Path(config.threat_file_path)
            if not threat_file.is_absolute():
                threat_file = Path(project_path) / threat_file
            if not threat_file.is_file():
                raise FileNotFoundError(
                    f"Threat file not found: {config.threat_file_path}"
                )

        # Look up the Application record (if this run is scoped to one) so we
        # can both pin the run-folder name to ``app.run_dir_name`` and seed
        # scanner_context.json from the business context before the pipeline
        # starts. Done upfront because the folder decision happens before
        # seeding.
        app_record = None
        if config.app_id and not config.resume_run_dir:
            try:
                app_record = get_app_repository().get_application(config.app_id)
            except ApplicationNotFoundError:
                # Route layer already rejects unknown app_ids with 404, but
                # guard here too so stale RunConfigs don't crash the executor.
                app_record = None

        # Resolve run directory — reuse existing dir on resume, create fresh otherwise
        if config.resume_run_dir:
            run_dir = Path(config.resume_run_dir)
            project_dir = run_dir.parent  # <runs_root>/<project_folder>/
        else:
            # For app-scoped runs, force the folder to the app's stable
            # ``run_dir_name`` so every version for a given Application lands
            # under the same folder — independent of the project path basename.
            # Also hand in the user-chosen display name so metadata.json
            # doesn't get stuck holding a cryptic project-basename fallback.
            forced_folder = app_record.run_dir_name if app_record else None
            forced_display_name = app_record.name if app_record else None
            run_dir, project_dir = create_run_directory(
                project_path,
                folder_name=forced_folder,
                display_name=forced_display_name,
            )
        run_dir_str = str(run_dir)

        # Tell the ScanControl where the run directory lives so that
        # RunManager.resume_run() can locate pause_state.json later.
        if scan_control is not None:
            scan_control.run_dir = run_dir_str

        # Seed scanner_context.json from the app's business context before any
        # agent runs. Skipped when the run isn't linked to a persisted app
        # (legacy / resume paths) — the scanner then writes a fresh file the
        # way it always has.
        if app_record is not None:
            _seed_scanner_context(run_dir, app_record)

        skip_nodes: frozenset[str] = frozenset(config.skip_nodes) if config.skip_nodes else frozenset()
        graph = build_graph(project_path, run_dir=run_dir_str, skip_nodes=skip_nodes, scan_control=scan_control, interaction_fn=interaction_fn)

        interrupted = False
        interrupted_intent = "stop"
        interrupted_stage = ""

        async def _run():
            nonlocal interrupted, interrupted_intent, interrupted_stage
            current_stage = ""
            current_node_id = ""
            prev_node_id = ""
            tool_count = 0
            last_tool_name = ""
            result = None
            poll_task = None
            completed_nodes: list[str] = []

            async def _poll_parallel_progress():
                """Poll parallel pipeline progress and emit updates.

                Emits progress on the single "Parallel Analysis" stage with
                per-threat worker status and filesystem-based sub-step messages.
                No stage transitions -- all parallel work is one UI stage.
                """
                import re as _re
                from threatforest.agents.parallel import get_parallel_progress

                state_dir = Path(run_dir_str) / "state"
                seen_files: set[str] = set()

                # Map per-threat file suffix to (emoji, human label)
                _FILE_TYPE_MAP = {
                    "attack_trees":     ("\U0001f333", "Attack tree for threat {n} generated"),
                    "ttp_candidates":   ("\U0001f4d0", "TTP embedding for threat {n} complete"),
                    "ttp_mappings":     ("\U0001f916", "TTP mapping for threat {n} reviewed"),
                    "mitigations":      ("\U0001f6e1\ufe0f", "Mitigations for threat {n} generated"),
                }

                tick = 0

                while True:
                    await asyncio.sleep(1)
                    tick += 1
                    pp = get_parallel_progress()
                    total = pp.get("total_threats", 0)
                    done = pp.get("completed_count", 0)
                    threat_status = pp.get("threat_status", {})

                    if not total:
                        progress_callback(ProgressEvent(
                            event_type="stage_progress",
                            stage="Parallel Analysis",
                            percentage=min(5, tick),
                            message="\u23f3 Initializing parallel pipeline\u2026",
                        ))
                        continue

                    # --- Filesystem scan for granular per-threat progress ---
                    latest_message = None
                    try:
                        current_files = {f.name for f in state_dir.iterdir() if f.is_file()}
                    except (OSError, PermissionError):
                        current_files = set()

                    new_files = sorted(current_files - seen_files)
                    for filename in new_files:
                        m = _re.match(r't(\d+)_(.+)\.json$', filename)
                        if m:
                            threat_idx = int(m.group(1))
                            file_type = m.group(2)
                            if file_type in _FILE_TYPE_MAP:
                                _emoji, _template = _FILE_TYPE_MAP[file_type]
                                latest_message = f"{_emoji} {_template.format(n=threat_idx + 1)}"

                    seen_files = current_files

                    # --- Progress event with per-worker status ---
                    pct = int(100 * done / total)

                    workers = []
                    for i in range(total):
                        if i in pp.get("completed_threats", set()):
                            workers.append({"id": i, "status": "completed", "stage": "\u2705 Done"})
                        elif i in threat_status:
                            ts = threat_status[i]
                            workers.append({"id": i, "status": "in-progress", "stage": ts.get("stage", ""), "detail": ts.get("detail", "")})
                        else:
                            workers.append({"id": i, "status": "pending", "stage": "\u23f3 Queued"})

                    message = latest_message or f"{done}/{total} threats completed"

                    progress_callback(ProgressEvent(
                        event_type="stage_progress",
                        stage="Parallel Analysis",
                        percentage=pct,
                        message=message,
                        details={"workers": workers, "total": total, "completed": done},
                    ))

            async for event in graph.stream_async("Run the ThreatForest threat modeling pipeline."):
                etype = event.get("type", "")

                if etype == "multiagent_node_start":
                    nid = event.get("node_id", "")
                    current_node_id = nid
                    tool_count = 0
                    last_tool_name = ""
                    stage = NODE_LABELS.get(nid, nid)
                    if stage != current_stage:
                        if current_stage:
                            # Send completion with summary for the previous stage
                            prev_summary = _get_stage_summary(project_path, prev_node_id, run_dir=run_dir_str) if prev_node_id else None
                            progress_callback(ProgressEvent(
                                event_type="stage_complete",
                                stage=current_stage,
                                percentage=100,
                                message=prev_summary.get("message", f"{current_stage} complete") if prev_summary else f"{current_stage} complete",
                                details=prev_summary or {},
                            ))
                        current_stage = stage
                        prev_node_id = nid
                        progress_callback(ProgressEvent(
                            event_type="stage_start",
                            stage=stage,
                            percentage=0,
                            message=f"Starting {stage}",
                        ))
                    # Start polling for parallel pipeline
                    if nid == "parallel_pipeline" and poll_task is None:
                        poll_task = asyncio.create_task(_poll_parallel_progress())

                elif etype == "multiagent_node_stop":
                    nid = event.get("node_id", "")
                    # When parallel pipeline completes, cancel the poller.
                    # The stage_complete for "Parallel Analysis" will be
                    # emitted by the normal node transition logic when the
                    # next node (report) starts, or by the final cleanup.
                    if nid == "parallel_pipeline" and poll_task:
                        poll_task.cancel()
                        poll_task = None

                    prev_node_id = nid
                    completed_nodes.append(nid)

                    # Expose completed nodes on ScanControl so the crash
                    # handler in RunManager can persist them to pause_state.
                    if scan_control is not None:
                        scan_control.completed_nodes = list(completed_nodes)

                    # Check for pause/stop at this natural stage boundary.
                    # We only interrupt between complete nodes so that no
                    # partial output is left on disk.
                    if scan_control is not None and scan_control.should_interrupt:
                        _save_pause_state(run_dir, completed_nodes, scan_control.intent, config)
                        interrupted = True
                        interrupted_intent = scan_control.intent
                        interrupted_stage = current_stage
                        verb = "paused" if scan_control.intent == "pause" else "stopped"
                        progress_callback(ProgressEvent(
                            event_type=f"scan_{verb}",
                            stage=current_stage or "unknown",
                            percentage=0,
                            message=(
                                f"Scan {verb} after completing stage. "
                                + ("Click Resume to continue." if verb == "paused" else "")
                            ),
                        ))
                        break

                elif etype == "multiagent_node_stream":
                    # Check for pause/stop during agent execution (mid-node).
                    # We break here WITHOUT appending to completed_nodes so the
                    # interrupted node is re-run from scratch on resume.
                    if scan_control is not None and scan_control.should_interrupt:
                        if poll_task:
                            poll_task.cancel()
                            poll_task = None
                        _save_pause_state(run_dir, completed_nodes, scan_control.intent, config)
                        interrupted = True
                        interrupted_intent = scan_control.intent
                        interrupted_stage = current_stage
                        verb = "paused" if scan_control.intent == "pause" else "stopped"
                        progress_callback(ProgressEvent(
                            event_type=f"scan_{verb}",
                            stage=current_stage or "unknown",
                            percentage=0,
                            message=(
                                f"Scan {verb} during stage. "
                                + ("Click Resume to continue." if verb == "paused" else "")
                            ),
                        ))
                        break

                    nested = event.get("event", {})
                    if isinstance(nested, dict):
                        tool_use = nested.get("current_tool_use", {})
                        tool_name = tool_use.get("name", "") if tool_use else ""
                        if tool_name and tool_name != last_tool_name:
                            last_tool_name = tool_name
                            tool_count += 1

                            expected = NODE_TOOL_ESTIMATES.get(current_node_id, 6)
                            pct = min(95, int(100 * tool_count / expected))

                            # Extract file path from tool input for context
                            tool_input = tool_use.get("input", {})
                            file_path = ""
                            if isinstance(tool_input, dict):
                                raw_path = tool_input.get("path", "")
                                if raw_path:
                                    # Show just the filename or last 2 path components
                                    parts = str(raw_path).replace("\\", "/").split("/")
                                    file_path = "/".join(parts[-2:]) if len(parts) > 1 else parts[-1]

                            # Use node-specific descriptions, fallback to generic
                            node_descs = NODE_TOOL_DESCRIPTIONS.get(current_node_id, {})
                            sub_step = node_descs.get(tool_name, TOOL_DESCRIPTIONS.get(tool_name, tool_name))
                            if file_path:
                                sub_step += f" — {file_path}"

                            # For threat generation: when writing, show specific message
                            if current_node_id == "threat" and tool_name == "sandboxed_file_write":
                                sub_step = "🧠 Writing threat statements…"
                                pct = 90

                            progress_callback(ProgressEvent(
                                event_type="stage_progress",
                                stage=current_stage,
                                percentage=pct,
                                message=sub_step,
                            ))

                        # For threat/report: emit "thinking" progress during long LLM phases
                        if (current_node_id in ("threat", "report") and tool_count >= 1
                                and tool_count <= 2 and not tool_name):
                            thinking_msgs = {
                                "threat": "🧠 Analyzing threat surface and generating statements…",
                                "report": "📝 Compiling analysis into dashboard…",
                            }
                            thinking_pct = min(80, 20 + tool_count * 15)
                            progress_callback(ProgressEvent(
                                event_type="stage_progress",
                                stage=current_stage,
                                percentage=thinking_pct,
                                message=thinking_msgs.get(current_node_id, "Processing…"),
                            ))

                if "result" in event:
                    result = event["result"]


            # Only emit the final stage_complete when the run finished naturally.
            # If interrupted (paused/stopped) the scan_paused/scan_stopped event
            # was already pushed and the stage should not be marked complete.
            if current_stage and not interrupted:
                final_summary = _get_stage_summary(project_path, prev_node_id, run_dir=run_dir_str) if prev_node_id else None
                progress_callback(ProgressEvent(
                    event_type="stage_complete",
                    stage=current_stage,
                    percentage=100,
                    message=final_summary.get("message", f"{current_stage} complete") if final_summary else f"{current_stage} complete",
                    details=final_summary or {},
                ))

            return result

        result = asyncio.run(_run())

        # Return early when the run was paused or stopped by the user.
        if interrupted:
            return {
                "status": interrupted_intent,
                "run_dir": run_dir_str,
                "paused_at_stage": interrupted_stage,
            }

        output_dir = str(run_dir / "output")

        # Clean up pause_state.json on successful completion so the run
        # no longer appears in the "paused runs" list.
        pause_file = run_dir / "pause_state.json"
        if pause_file.is_file():
            pause_file.unlink()

        # Update metadata.json description from scan output
        try:
            import json as _json
            data_file = run_dir / "output" / "threatforest_data.json"
            if data_file.is_file():
                data = _json.loads(data_file.read_text(encoding="utf-8"))
                short_summary = (data.get("project_info") or {}).get("short_summary", "")
                if short_summary:
                    meta_file = project_dir / "metadata.json"
                    if meta_file.is_file():
                        meta = _json.loads(meta_file.read_text(encoding="utf-8"))
                        meta["description"] = short_summary
                        meta_file.write_text(_json.dumps(meta, indent=2), encoding="utf-8")
        except Exception:
            pass

        # Check interviewer confidence for low-confidence warning
        low_confidence = False
        try:
            import json as _json2
            ctx_file = run_dir / "state" / "scanner_context.json"
            if ctx_file.is_file():
                ctx = _json2.loads(ctx_file.read_text(encoding="utf-8"))
                low_confidence = ctx.get("interviewer_confidence") == "low"
        except Exception:
            pass

        result_dict = {
            "output_dir": output_dir,
            "run_dir": run_dir_str,
            "app_id": slugify(project_dir.name),
        }
        if low_confidence:
            result_dict["low_confidence"] = True
        return result_dict

    return executor
