"""Graph assembly — wires all agents into a Strands Graph.

This is the v2 pipeline entry point, replacing orchestrator.py.
"""

import json
from pathlib import Path
from typing import Any, AsyncIterator

from strands import Agent
from strands.multiagent.base import MultiAgentBase, MultiAgentResult, NodeResult, Status
from strands.multiagent.graph import Graph, GraphNode, GraphEdge, GraphState
from strands.agent.agent_result import AgentResult
from strands.types.content import ContentBlock

from threatforest.agents.scanner.agent import STATE_DIR


# ---------------------------------------------------------------------------
# Lightweight wrapper: run a plain function as a GraphNode executor
# ---------------------------------------------------------------------------

class FunctionAgent(MultiAgentBase):
    """Wraps a plain function so it can be used as a GraphNode executor.

    The function receives (repo_path, task_text) and returns a result string.
    """

    def __init__(self, fn, repo_path: str, node_id: str):
        self.fn = fn
        self.repo_path = repo_path
        self.id = node_id

    async def invoke_async(self, task, invocation_state=None, **kwargs):
        result_str = self.fn(self.repo_path)
        # Build a minimal AgentResult-like object
        agent_result = _make_agent_result(str(result_str or "done"))
        return MultiAgentResult(
            status=Status.COMPLETED,
            results={self.id: NodeResult(result=agent_result, status=Status.COMPLETED)},
        )


def _make_agent_result(text: str) -> AgentResult:
    """Create a minimal AgentResult from a text string."""
    from strands.types.content import Message
    from strands.telemetry.metrics import EventLoopMetrics

    msg = Message(role="assistant", content=[ContentBlock(text=text)])
    return AgentResult(stop_reason="end_turn", message=msg, metrics=EventLoopMetrics(), state={})


# ---------------------------------------------------------------------------
# Conditional helpers
# ---------------------------------------------------------------------------

def _is_aws_project(repo_path: str) -> bool:
    ctx_file = Path(repo_path) / STATE_DIR / "scanner_context.json"
    if not ctx_file.exists():
        return False
    try:
        return json.loads(ctx_file.read_text()).get("cloud_provider", "").lower() == "aws"
    except (json.JSONDecodeError, OSError):
        return False


def _verifier_passed(repo_path: str, verifier_fn) -> bool:
    passed, _ = verifier_fn(repo_path)
    return passed


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_graph(repo_path: str) -> Graph:
    """Build the full ThreatForest graph for a repository."""
    from threatforest.agents.scanner.agent import create_scanner_agent
    from threatforest.agents.scanner.verifier import verify_scanner_output
    from threatforest.agents.threat.agent import create_threat_agent
    from threatforest.agents.threat.verifier import verify_threat_output
    from threatforest.agents.parallel import run_parallel_pipeline
    from threatforest.agents.mitigation.verifier import verify_mitigation_output
    from threatforest.agents.report.agent import run_report_generator
    from threatforest.agents.report.verifier import verify_report_output

    state_dir = Path(repo_path) / STATE_DIR
    state_dir.mkdir(parents=True, exist_ok=True)

    # --- Nodes ---
    scanner = GraphNode("scanner", create_scanner_agent(repo_path))
    scanner_v = GraphNode("scanner_verifier", FunctionAgent(
        lambda rp: verify_scanner_output(str(Path(rp) / STATE_DIR / "scanner_context.json")),
        repo_path, "scanner_verifier",
    ))

    threat = GraphNode("threat", create_threat_agent(repo_path))
    threat_v = GraphNode("threat_verifier", FunctionAgent(
        lambda rp: verify_threat_output(str(Path(rp) / STATE_DIR / "threats.json")),
        repo_path, "threat_verifier",
    ))

    # Parallel fan-out: tree → ttp → mitigation per threat
    parallel = GraphNode("parallel_pipeline", FunctionAgent(
        run_parallel_pipeline, repo_path, "parallel_pipeline",
    ))
    parallel_v = GraphNode("parallel_verifier", FunctionAgent(
        lambda rp: verify_mitigation_output(rp),
        repo_path, "parallel_verifier",
    ))

    report = GraphNode("report", FunctionAgent(
        run_report_generator, repo_path, "report",
    ))
    report_v = GraphNode("report_verifier", FunctionAgent(
        lambda rp: verify_report_output(rp),
        repo_path, "report_verifier",
    ))

    # --- Edges ---
    edges = {
        # Scanner → Threat (sequential, fast)
        GraphEdge(scanner, scanner_v),
        GraphEdge(scanner_v, threat,
                  condition=lambda s: _verifier_passed(repo_path,
                      lambda rp: verify_scanner_output(str(Path(rp) / STATE_DIR / "scanner_context.json")))),
        GraphEdge(threat, threat_v),

        # Threat → Parallel pipeline (fan-out)
        GraphEdge(threat_v, parallel,
                  condition=lambda s: _verifier_passed(repo_path,
                      lambda rp: verify_threat_output(str(Path(rp) / STATE_DIR / "threats.json")))),
        GraphEdge(parallel, parallel_v),

        # Parallel → Report
        GraphEdge(parallel_v, report,
                  condition=lambda s: _verifier_passed(repo_path, lambda rp: verify_mitigation_output(rp))),
        GraphEdge(report, report_v),

        # Retry edges
        GraphEdge(scanner_v, scanner,
                  condition=lambda s: not _verifier_passed(repo_path,
                      lambda rp: verify_scanner_output(str(Path(rp) / STATE_DIR / "scanner_context.json")))),
        GraphEdge(threat_v, threat,
                  condition=lambda s: not _verifier_passed(repo_path,
                      lambda rp: verify_threat_output(str(Path(rp) / STATE_DIR / "threats.json")))),
        GraphEdge(parallel_v, parallel,
                  condition=lambda s: not _verifier_passed(repo_path, lambda rp: verify_mitigation_output(rp))),
        GraphEdge(report_v, report,
                  condition=lambda s: not _verifier_passed(repo_path, lambda rp: verify_report_output(rp))),
    }

    nodes = {
        "scanner": scanner, "scanner_verifier": scanner_v,
        "threat": threat, "threat_verifier": threat_v,
        "parallel_pipeline": parallel, "parallel_verifier": parallel_v,
        "report": report, "report_verifier": report_v,
    }

    return Graph(
        nodes=nodes,
        edges=edges,
        entry_points={scanner},
        max_node_executions=50,  # total budget across all nodes (14 nodes × ~3 each + retries)
        reset_on_revisit=True,
        id="threatforest",
    )


async def run_graph(repo_path: str) -> dict:
    """Run the full ThreatForest graph and return the result."""
    import time as _time
    from rich.console import Console
    from rich.live import Live
    from rich.text import Text
    from rich.table import Table

    from threatforest.agents.tracing_session import init_session, setup_langfuse_otel
    setup_langfuse_otel()
    init_session()

    console = Console()

    graph = build_graph(repo_path)

    NODE_LABELS = {
        "scanner": "🔍 Scanner Agent",
        "scanner_verifier": "✅ Scanner Verifier",
        "threat": "🤖 Threat Agent",
        "threat_verifier": "✅ Threat Verifier",
        "parallel_pipeline": "⚡ Parallel Pipeline (tree → ttp → mitigation)",
        "parallel_verifier": "✅ Pipeline Verifier",
        "report": "📝 Report Generator",
        "report_verifier": "✅ Report Verifier",
    }

    def _node_summary(nid: str) -> list[str]:
        """Read state files to produce summary lines for a completed node."""
        sd = Path(repo_path) / STATE_DIR
        try:
            if nid == "scanner":
                d = json.loads((sd / "scanner_context.json").read_text())
                lines = [
                    f"Cloud: {d.get('cloud_provider', '?').upper()}",
                    f"Stack: {d.get('tech_stack', '')[:80]}",
                    f"Services: {', '.join(d.get('services', [])[:6])}",
                    f"Auth: {', '.join(d.get('auth_mechanisms', [])[:4]) or 'none detected'}",
                    f"Files analyzed: {len(d.get('files_analyzed', []))}",
                ]
                return lines
            elif nid == "scanner_verifier":
                f = sd / "scanner_context.json"
                if f.exists():
                    from threatforest.agents.scanner.verifier import verify_scanner_output
                    ok, msg = verify_scanner_output(str(f))
                    return [f"{'PASS' if ok else 'FAIL'}: {msg}"]
            elif nid == "threat":
                d = json.loads((sd / "threats.json").read_text())
                threats = d.get("threats", [])
                lines = [f"{len(threats)} threats identified"]
                for t in threats[:5]:
                    sev = t.get("severity", "?")
                    desc = t.get("description", t.get("name", ""))[:70]
                    lines.append(f"  [{sev.upper()}] {desc}")
                if len(threats) > 5:
                    lines.append(f"  … and {len(threats) - 5} more")
                return lines
            elif nid == "threat_verifier":
                f = sd / "threats.json"
                if f.exists():
                    from threatforest.agents.threat.verifier import verify_threat_output
                    ok, msg = verify_threat_output(str(f))
                    return [f"{'PASS' if ok else 'FAIL'}: {msg}"]
            elif nid == "parallel_pipeline":
                trees = json.loads((sd / "attack_trees.json").read_text()).get("attack_trees", [])
                mappings = json.loads((sd / "ttp_mappings.json").read_text()).get("ttp_mappings", [])
                mits_raw = (sd / "mitigations.json").read_text().replace(",\n]", "\n]").replace(",]", "]")
                mits = json.loads(mits_raw).get("mitigations", [])
                total_steps = sum(len(t.get("steps", [])) for t in trees)
                techniques = {m.get("technique_id") for m in mappings if m.get("technique_id")}
                lines = [
                    f"{len(trees)} attack trees · {total_steps} steps",
                    f"{len(mappings)} TTP mappings · {len(techniques)} unique techniques",
                    f"{len(mits)} mitigations",
                ]
                for t in trees[:4]:
                    goal = t.get("root_goal", "")[:60]
                    n = len(t.get("steps", []))
                    lines.append(f"  🌳 {goal} ({n} steps)")
                if len(trees) > 4:
                    lines.append(f"  … and {len(trees) - 4} more trees")
                return lines
            elif nid == "parallel_verifier":
                from threatforest.agents.mitigation.verifier import verify_mitigation_output
                ok, msg = verify_mitigation_output(repo_path)
                return [f"{'PASS' if ok else 'FAIL'}: {msg}"]
            elif nid == "report":
                f = Path(repo_path) / ".threatforest/output/threat_model_report.md"
                if f.exists():
                    content = f.read_text()
                    sections = [l for l in content.splitlines() if l.startswith("## ")]
                    return [f"Report written · {len(content.splitlines())} lines · {len(sections)} sections"]
            elif nid == "report_verifier":
                from threatforest.agents.report.verifier import verify_report_output
                ok, msg = verify_report_output(repo_path)
                return [f"{'PASS' if ok else 'FAIL'}: {msg}"]
        except Exception:
            pass
        return []

    SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spin_idx = 0
    current_node = ""
    current_node_id = ""
    tool_count = 0
    prev_tool_name = None
    node_start_time = 0.0
    completed = []  # list of (label, summary_lines, seconds)
    result = None

    with Live(Text(""), console=console, refresh_per_second=4, transient=False) as live:

        def _render():
            nonlocal spin_idx
            spin_idx = (spin_idx + 1) % len(SPINNER)
            table = Table.grid(padding=(0, 1))
            table.add_column()
            for label, summary_lines, secs in completed:
                table.add_row(f"{label}  [green]✓[/green] [dim]{secs:.0f}s[/dim]")
                for line in summary_lines:
                    table.add_row(f"  [dim]{line}[/dim]")
            if current_node:
                elapsed = _time.time() - node_start_time
                spinner = SPINNER[spin_idx]

                # For parallel pipeline, show per-threat progress
                if current_node_id == "parallel_pipeline":
                    from threatforest.agents.parallel import get_parallel_progress
                    pp = get_parallel_progress()
                    total = pp.get("total_threats", 0)
                    done = pp.get("completed_count", 0)
                    stage = pp.get("stage", "")
                    detail = pp.get("detail", "")

                    if total:
                        bar_filled = int(20 * done / total)
                        bar = "█" * bar_filled + "░" * (20 - bar_filled)
                        pct = int(100 * done / total)
                        active = f"[cyan]{spinner}[/cyan] {current_node}  [dim]{elapsed:.0f}s[/dim]"
                        table.add_row(active)
                        table.add_row(f"  [cyan]{bar}[/cyan] {done}/{total} threats  [dim]{pct}%[/dim]")
                        if stage:
                            line = f"  [dim]{stage}[/dim]"
                            if detail:
                                line += f" [dim]— {detail}[/dim]"
                            table.add_row(line)
                    else:
                        table.add_row(f"[cyan]{spinner}[/cyan] {current_node}  [dim]{elapsed:.0f}s  starting…[/dim]")
                else:
                    active = f"[cyan]{spinner}[/cyan] {current_node}  [dim]{elapsed:.0f}s[/dim]"
                    if prev_tool_name:
                        active += f"  [cyan]🔧 {prev_tool_name} ({tool_count})[/cyan]"
                    table.add_row(active)
            return table

        import asyncio as _asyncio

        async def _spin():
            while True:
                await _asyncio.sleep(0.15)
                live.update(_render())

        spin_task = _asyncio.create_task(_spin())

        try:
          async for event in graph.stream_async("Run the ThreatForest threat modeling pipeline."):
            etype = event.get("type", "")

            if etype == "multiagent_node_start":
                nid = event.get("node_id", "")
                current_node = NODE_LABELS.get(nid, nid)
                current_node_id = nid
                tool_count = 0
                prev_tool_name = None
                node_start_time = _time.time()
                live.update(_render())

            elif etype == "multiagent_node_stop":
                nid = event.get("node_id", "")
                label = NODE_LABELS.get(nid, nid)
                elapsed = _time.time() - node_start_time
                summary = _node_summary(nid)
                completed.append((label, summary, elapsed))
                current_node = ""
                prev_tool_name = None
                live.update(_render())

            elif etype == "multiagent_node_stream":
                nested = event.get("event", {})
                if isinstance(nested, dict):
                    tool_use = nested.get("current_tool_use", {})
                    tool_name = tool_use.get("name", "") if tool_use else ""
                    if tool_name and tool_name != prev_tool_name:
                        prev_tool_name = tool_name
                        tool_count += 1
                        live.update(_render())

            if "result" in event:
                result = event["result"]
        finally:
            spin_task.cancel()

    if result is None:
        return {"status": "failed", "error": "Graph produced no result"}

    failed = []
    for nid, nr in result.results.items():
        if nr.status == Status.FAILED:
            failed.append(f"{nid}: {nr.result}")

    output = {
        "status": "success" if result.status == Status.COMPLETED else "failed",
        "execution_count": result.execution_count,
        "output_dir": str(Path(repo_path) / ".threatforest" / "output"),
        "output_directory": str(Path(repo_path) / ".threatforest" / "output"),
    }
    if failed:
        output["error"] = "; ".join(failed)
    return output
