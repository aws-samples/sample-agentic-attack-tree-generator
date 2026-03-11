"""Executor that bridges RunManager to the ThreatForest graph pipeline.

Reads configuration from ``.threatforest/config.yaml``, syncs it to the
engine's expected location, and runs the v2 graph pipeline.  Progress
events from the graph stream are forwarded to the RunManager callback.
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from typing import Any, Callable

import yaml

from server.models import RunConfig
from server.run_manager import OrchestratorExecutor, ProgressEvent


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


NODE_LABELS = {
    "scanner": "Repository Analysis",
    "scanner_verifier": "Repository Analysis",
    "threat": "Threat Generation",
    "threat_verifier": "Threat Generation",
    "parallel_pipeline": "Attack Tree Generation",
    "parallel_verifier": "Attack Tree Generation",
    "report": "Dashboard Generation",
    "report_verifier": "Dashboard Generation",
}

# Map parallel pipeline internal stages to frontend stage names
PARALLEL_STAGE_MAP = {
    "🌳 Tree": "Attack Tree Generation",
    "📐 TTP Embed": "TTP Enrichment",
    "🤖 TTP Review": "TTP Enrichment",
    "🛡️ Mitigation": "Mitigation Mapping",
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

# Human-readable descriptions for tool names
TOOL_DESCRIPTIONS = {
    "structural_analyzer": "📂 Scanning project structure",
    "sandboxed_file_read": "📄 Reading project files",
    "sandboxed_file_write": "💾 Writing analysis results",
}


def _get_stage_summary(project_path: str, node_id: str) -> dict | None:
    """Read state files and return a summary dict for the completed node."""
    import json as _json
    sd = Path(project_path) / ".threatforest" / "state"
    try:
        if node_id in ("scanner", "scanner_verifier"):
            d = _json.loads((sd / "scanner_context.json").read_text())
            return {
                "message": f"Analyzed {len(d.get('files_analyzed', []))} files",
                "findings": [
                    f"☁️ Cloud: {d.get('cloud_provider', 'unknown').upper()}",
                    f"🔧 Stack: {d.get('tech_stack', '')[:80]}",
                    f"📦 Services: {', '.join(d.get('services', [])[:6])}",
                    f"🔐 Auth: {', '.join(d.get('auth_mechanisms', [])[:4]) or 'none detected'}",
                ],
            }
        elif node_id in ("threat", "threat_verifier"):
            d = _json.loads((sd / "threats.json").read_text())
            threats = d.get("threats", [])
            findings = [f"{len(threats)} threats identified"]
            for t in threats[:5]:
                sev = t.get("priority") or t.get("severity") or "medium"
                title = t.get("title", t.get("name", t.get("description", "")))[:60]
                findings.append(f"  [{sev.upper()}] {title}")
            if len(threats) > 5:
                findings.append(f"  … and {len(threats) - 5} more")
            return {"message": f"{len(threats)} threats identified", "findings": findings}
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
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        pass
    return None


def create_orchestrator_executor(workspace_dir: Path) -> OrchestratorExecutor:
    """Return an executor that runs the ThreatForest graph pipeline."""
    threatforest_src = workspace_dir / "src"

    def executor(
        config: RunConfig,
        progress_callback: Callable[[ProgressEvent], None],
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

        project_path = str(Path(config.project_path).expanduser().resolve())
        if not Path(project_path).is_dir():
            # Try resolving relative to workspace
            candidate = workspace_dir / config.project_path
            if candidate.is_dir():
                project_path = str(candidate.resolve())
        graph = build_graph(project_path)

        async def _run():
            current_stage = ""
            current_node_id = ""
            prev_node_id = ""
            tool_count = 0
            last_tool_name = ""
            result = None
            poll_task = None

            async def _poll_parallel_progress():
                """Poll parallel pipeline progress and forward to WebSocket."""
                from threatforest.agents.parallel import get_parallel_progress
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
                            stage=current_stage,
                            percentage=min(5, tick),
                            message="⏳ Initializing parallel pipeline…",
                        ))
                        continue

                    pct = int(100 * done / total)

                    # Build per-worker status for the UI
                    workers = []
                    for i in range(total):
                        if i in pp.get("completed_threats", set()):
                            workers.append({"id": i, "status": "completed", "stage": "✅ Done"})
                        elif i in threat_status:
                            ts = threat_status[i]
                            workers.append({"id": i, "status": "in-progress", "stage": ts.get("stage", ""), "detail": ts.get("detail", "")})
                        else:
                            workers.append({"id": i, "status": "pending", "stage": "⏳ Queued"})

                    progress_callback(ProgressEvent(
                        event_type="stage_progress",
                        stage=current_stage,
                        percentage=pct,
                        message=f"{done}/{total} threats completed",
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
                            prev_summary = _get_stage_summary(project_path, prev_node_id) if prev_node_id else None
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
                    # When parallel pipeline completes, send all intermediate stages with summaries
                    if nid == "parallel_pipeline" and poll_task:
                        poll_task.cancel()
                        poll_task = None
                        ps = _get_stage_summary(project_path, "parallel_pipeline")
                        findings = ps.get("findings", []) if ps else []
                        stage_findings = {
                            "Attack Tree Generation": findings[:1],
                            "TTP Enrichment": findings[1:2],
                            "Mitigation Mapping": findings[2:],
                        }
                        for stage_name in ["Attack Tree Generation", "TTP Enrichment", "Mitigation Mapping"]:
                            progress_callback(ProgressEvent(
                                event_type="stage_start",
                                stage=stage_name,
                                percentage=0,
                                message=f"Starting {stage_name}",
                            ))
                            progress_callback(ProgressEvent(
                                event_type="stage_complete",
                                stage=stage_name,
                                percentage=100,
                                message=f"{stage_name} complete",
                                details={"findings": stage_findings.get(stage_name, [])},
                            ))
                        current_stage = "Mitigation Mapping"

                    prev_node_id = nid

                elif etype == "multiagent_node_stream":
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

                            sub_step = TOOL_DESCRIPTIONS.get(tool_name, tool_name)
                            if file_path:
                                sub_step += f" — {file_path}"

                            progress_callback(ProgressEvent(
                                event_type="stage_progress",
                                stage=current_stage,
                                percentage=pct,
                                message=sub_step,
                            ))

                if "result" in event:
                    result = event["result"]

            if current_stage:
                final_summary = _get_stage_summary(project_path, prev_node_id) if prev_node_id else None
                progress_callback(ProgressEvent(
                    event_type="stage_complete",
                    stage=current_stage,
                    percentage=100,
                    message=final_summary.get("message", f"{current_stage} complete") if final_summary else f"{current_stage} complete",
                    details=final_summary or {},
                ))

            return result

        result = asyncio.run(_run())

        output_dir = str(Path(project_path) / ".threatforest" / "output")
        dashboard_path = ""
        candidate = Path(output_dir) / "attack_trees_dashboard.html"
        if candidate.is_file():
            dashboard_path = str(candidate)

        project_name = Path(config.project_path).name
        return {
            "output_dir": output_dir,
            "dashboard_path": dashboard_path,
            "app_id": _slugify(project_name),
        }

    return executor
