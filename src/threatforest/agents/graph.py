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

from threatforest.agents.scanner.agent import STATE_DIR, resolve_state_dir
from threatforest.agents.report.agent import _resolve_output_dir

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from server.scan_control import ScanControl


# ---------------------------------------------------------------------------
# Lightweight wrapper: run a plain function as a GraphNode executor
# ---------------------------------------------------------------------------

class FunctionAgent(MultiAgentBase):
    """Wraps a plain function so it can be used as a GraphNode executor.

    The function receives (repo_path) and returns a result string.
    When *run_dir* is set, the function is called as fn(repo_path, run_dir=run_dir).
    Additional keyword arguments (e.g. scan_control) are forwarded as-is.
    """

    def __init__(self, fn, repo_path: str, node_id: str, run_dir: str | None = None, **extra_kwargs):
        self.fn = fn
        self.repo_path = repo_path
        self.run_dir = run_dir
        self.extra_kwargs = extra_kwargs
        self.id = node_id

    async def invoke_async(self, task, invocation_state=None, **kwargs):
        import asyncio
        call_kwargs = {}
        if self.run_dir:
            call_kwargs["run_dir"] = self.run_dir
        call_kwargs.update(self.extra_kwargs)
        result_str = await asyncio.to_thread(self.fn, self.repo_path, **call_kwargs)
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

def _is_aws_project(repo_path: str, run_dir: str | None = None) -> bool:
    state_dir = resolve_state_dir(repo_path, run_dir)
    ctx_file = state_dir / "scanner_context.json"
    if not ctx_file.exists():
        return False
    try:
        return json.loads(ctx_file.read_text()).get("cloud_provider", "").lower() == "aws"
    except (json.JSONDecodeError, OSError):
        return False


def _verifier_passed(repo_path: str, verifier_fn, run_dir: str | None = None) -> bool:
    if run_dir:
        passed, _ = verifier_fn(repo_path, run_dir=run_dir)
    else:
        passed, _ = verifier_fn(repo_path)
    return passed


def _verifier_passed_file(verifier_fn, file_path: str) -> bool:
    """For verifiers that take a file path instead of repo_path (scanner, threat)."""
    passed, _ = verifier_fn(file_path)
    return passed


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def _make_skip_node(node_id: str, repo_path: str, run_dir: str | None) -> GraphNode:
    """Return a GraphNode that completes instantly without running the real agent.

    Used during a resumed run for nodes whose output files already exist on disk.
    The edge condition functions read from disk directly, so they will still
    evaluate correctly even though the real agent was skipped.
    """
    return GraphNode(node_id, FunctionAgent(
        fn=lambda rp, **kw: f"[skipped] {node_id} — output already on disk",
        repo_path=repo_path,
        node_id=node_id,
        run_dir=run_dir,
    ))


def build_graph(
    repo_path: str,
    run_dir: str | None = None,
    skip_nodes: frozenset[str] | None = None,
    scan_control: "ScanControl | None" = None,
    interaction_fn=None,
    frameworks: list[str] | None = None,
) -> Graph:
    """Build the full ThreatForest graph for a repository.

    Parameters
    ----------
    repo_path:
        Absolute path to the project repository.
    run_dir:
        Path to the centralized run directory where state and output are stored.
    skip_nodes:
        Set of graph node IDs whose outputs already exist on disk (from a prior
        paused/stopped run).  Those nodes are replaced with instant no-op agents
        so the graph can resume from the first incomplete node.
    scan_control:
        Optional ScanControl instance.  When provided, an InterruptHookProvider
        is injected into each Strands Agent so that pause/stop take effect at
        tool-call granularity rather than waiting for an entire node to finish.
    interaction_fn:
        Optional callable for the interviewer node's human-in-the-loop flow.
        Receives a list of strands Interrupt objects and returns interrupt
        responses, or None to skip the interview.
    """
    skip_nodes = skip_nodes or frozenset()

    from threatforest.agents.scanner.agent import create_scanner_agent
    from threatforest.agents.scanner.verifier import verify_scanner_output
    from threatforest.agents.interviewer.agent import create_interviewer_agent, InterviewerNode, ScannerReviewNode
    from threatforest.agents.threat.agent import create_threat_agent
    from threatforest.agents.threat.verifier import verify_threat_output
    from threatforest.agents.threat_review.agent import ThreatReviewNode
    from threatforest.agents.parallel import run_parallel_pipeline
    from threatforest.agents.mitigation.verifier import verify_mitigation_output
    from threatforest.agents.probability.stage import run_probability_stage
    from threatforest.agents.report.agent import run_report_generator
    from threatforest.agents.report.verifier import verify_report_output

    state_dir = resolve_state_dir(repo_path, run_dir)

    # --- Nodes ---
    scanner = (
        _make_skip_node("scanner", repo_path, run_dir)
        if "scanner" in skip_nodes
        else GraphNode("scanner", create_scanner_agent(repo_path, run_dir=run_dir))
    )

    def _verify_scanner(rp, run_dir=run_dir):
        sd = resolve_state_dir(rp, run_dir)
        return verify_scanner_output(str(sd / "scanner_context.json"))

    scanner_v = (
        _make_skip_node("scanner_verifier", repo_path, run_dir)
        if "scanner_verifier" in skip_nodes
        else GraphNode("scanner_verifier", FunctionAgent(
            lambda rp, **kw: _verify_scanner(rp),
            repo_path, "scanner_verifier", run_dir=run_dir,
        ))
    )

    # Scanner review: present findings for user confirmation before interview
    if "scanner_review" in skip_nodes:
        scanner_review = _make_skip_node("scanner_review", repo_path, run_dir)
    else:
        scanner_review = GraphNode("scanner_review", ScannerReviewNode(
            state_dir, interaction_fn, "scanner_review",
        ))

    # Interviewer: human-in-the-loop context validation
    if "interviewer" in skip_nodes:
        interviewer = _make_skip_node("interviewer", repo_path, run_dir)
    else:
        interviewer_agent = create_interviewer_agent(repo_path, run_dir=run_dir)
        interviewer = GraphNode("interviewer", InterviewerNode(
            interviewer_agent, interaction_fn, state_dir, "interviewer",
        ))

    threat = (
        _make_skip_node("threat", repo_path, run_dir)
        if "threat" in skip_nodes
        else GraphNode("threat", create_threat_agent(repo_path, run_dir=run_dir))
    )

    def _verify_threat(rp, run_dir=run_dir):
        sd = resolve_state_dir(rp, run_dir)
        return verify_threat_output(str(sd / "threats.json"))

    threat_v = (
        _make_skip_node("threat_verifier", repo_path, run_dir)
        if "threat_verifier" in skip_nodes
        else GraphNode("threat_verifier", FunctionAgent(
            lambda rp, **kw: _verify_threat(rp),
            repo_path, "threat_verifier", run_dir=run_dir,
        ))
    )

    # Threat review: HITL review of generated threats before parallel fan-out
    if "threat_review" in skip_nodes:
        threat_review = _make_skip_node("threat_review", repo_path, run_dir)
    else:
        threat_review = GraphNode("threat_review", ThreatReviewNode(
            state_dir, repo_path, run_dir, interaction_fn, "threat_review",
        ))

    # Parallel fan-out: tree -> ttp -> mitigation per threat
    parallel = (
        _make_skip_node("parallel_pipeline", repo_path, run_dir)
        if "parallel_pipeline" in skip_nodes
        else GraphNode("parallel_pipeline", FunctionAgent(
            run_parallel_pipeline, repo_path, "parallel_pipeline", run_dir=run_dir,
            scan_control=scan_control, frameworks=frameworks,
        ))
    )
    parallel_v = (
        _make_skip_node("parallel_verifier", repo_path, run_dir)
        if "parallel_verifier" in skip_nodes
        else GraphNode("parallel_verifier", FunctionAgent(
            lambda rp, **kw: verify_mitigation_output(rp, run_dir=kw.get("run_dir")),
            repo_path, "parallel_verifier", run_dir=run_dir,
        ))
    )

    # Probability stage — pure-Python, runs after mitigations are consolidated
    # and before the report generator consumes the tree state.
    probability = (
        _make_skip_node("probability", repo_path, run_dir)
        if "probability" in skip_nodes
        else GraphNode("probability", FunctionAgent(
            run_probability_stage, repo_path, "probability", run_dir=run_dir,
        ))
    )

    report = (
        _make_skip_node("report", repo_path, run_dir)
        if "report" in skip_nodes
        else GraphNode("report", FunctionAgent(
            run_report_generator, repo_path, "report", run_dir=run_dir,
        ))
    )
    report_v = (
        _make_skip_node("report_verifier", repo_path, run_dir)
        if "report_verifier" in skip_nodes
        else GraphNode("report_verifier", FunctionAgent(
            lambda rp, **kw: verify_report_output(rp, run_dir=kw.get("run_dir")),
            repo_path, "report_verifier", run_dir=run_dir,
        ))
    )

    # --- Edges ---
    def _scanner_ok(s):
        sd = resolve_state_dir(repo_path, run_dir)
        return _verifier_passed_file(verify_scanner_output, str(sd / "scanner_context.json"))

    def _scanner_fail(s):
        return not _scanner_ok(s)

    def _threat_ok(s):
        sd = resolve_state_dir(repo_path, run_dir)
        return _verifier_passed_file(verify_threat_output, str(sd / "threats.json"))

    def _threat_fail(s):
        return not _threat_ok(s)

    def _parallel_ok(s):
        return _verifier_passed(repo_path, verify_mitigation_output, run_dir=run_dir)

    def _parallel_fail(s):
        return not _parallel_ok(s)

    def _report_ok(s):
        return _verifier_passed(repo_path, verify_report_output, run_dir=run_dir)

    def _report_fail(s):
        return not _report_ok(s)

    edges = {
        # Scanner → Scanner Review → Interviewer → Threat
        GraphEdge(scanner, scanner_v),
        GraphEdge(scanner_v, scanner_review, condition=_scanner_ok),
        GraphEdge(scanner_review, interviewer),
        GraphEdge(interviewer, threat),
        GraphEdge(threat, threat_v),

        # Threat → Threat Review → Parallel pipeline (fan-out)
        GraphEdge(threat_v, threat_review, condition=_threat_ok),
        GraphEdge(threat_review, parallel),
        GraphEdge(parallel, parallel_v),

        # Parallel → Probability → Report
        GraphEdge(parallel_v, probability, condition=_parallel_ok),
        GraphEdge(probability, report),
        GraphEdge(report, report_v),

        # Retry edges
        GraphEdge(scanner_v, scanner, condition=_scanner_fail),
        GraphEdge(threat_v, threat, condition=_threat_fail),
        GraphEdge(parallel_v, parallel, condition=_parallel_fail),
        GraphEdge(report_v, report, condition=_report_fail),
    }

    nodes = {
        "scanner": scanner, "scanner_verifier": scanner_v,
        "scanner_review": scanner_review, "interviewer": interviewer,
        "threat": threat, "threat_verifier": threat_v,
        "threat_review": threat_review,
        "parallel_pipeline": parallel, "parallel_verifier": parallel_v,
        "probability": probability,
        "report": report, "report_verifier": report_v,
    }

    return Graph(
        nodes=nodes,
        edges=edges,
        entry_points={scanner},
        max_node_executions=32,
        reset_on_revisit=True,
        id="threatforest",
    )


async def run_graph(repo_path: str, run_dir: str | None = None, frameworks: list[str] | None = None, interaction_fn=None) -> dict:
    """Run the full ThreatForest graph and return the result."""
    import time as _time
    from rich.console import Console
    from rich.live import Live
    from rich.text import Text
    from rich.table import Table

    from threatforest.agents.tracing_session import init_session, setup_langfuse_otel
    setup_langfuse_otel()
    sid = init_session()

    from threatforest.agents import annotation_traces
    annotation_traces.init(sid)

    console = Console()

    graph = build_graph(repo_path, run_dir=run_dir, interaction_fn=interaction_fn, frameworks=frameworks)

    # Resolve dirs for reading state/output in _node_summary
    _state_dir = resolve_state_dir(repo_path, run_dir)
    _output_dir = _resolve_output_dir(repo_path, run_dir)

    NODE_LABELS = {
        "scanner": "🔍 Scanner Agent",
        "scanner_verifier": "✅ Scanner Verifier",
        "scanner_review": "📋 Scanner Review",
        "interviewer": "🔎 Context Validation",
        "threat": "🤖 Threat Agent",
        "threat_verifier": "✅ Threat Verifier",
        "threat_review": "📋 Threat Review",
        "parallel_pipeline": "⚡ Parallel Pipeline (tree → ttp → mitigation)",
        "parallel_verifier": "✅ Pipeline Verifier",
        "probability": "📊 Probability Stage",
        "report": "📝 Report Generator",
        "report_verifier": "✅ Report Verifier",
    }

    def _node_summary(nid: str) -> list[str]:
        """Read state files to produce summary lines for a completed node."""
        sd = _state_dir
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
            elif nid == "scanner_review":
                d = json.loads((sd / "scanner_context.json").read_text())
                reviewed = "yes" if d.get("scanner_review_applied") else "no edits"
                return [f"Review: {reviewed}"]
            elif nid == "interviewer":
                d = json.loads((sd / "scanner_context.json").read_text())
                confidence = d.get("interviewer_confidence", "skipped")
                summary = d.get("interviewer_summary", "")
                lines = [f"Confidence: {confidence}"]
                if summary:
                    lines.append(summary[:80])
                return lines
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
            elif nid == "threat_review":
                try:
                    d = json.loads((sd / "threats.json").read_text())
                    n = len(d.get("threats", []))
                    return [f"Threat review complete · {n} threats after review"]
                except (FileNotFoundError, json.JSONDecodeError):
                    return ["Threat review complete"]
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
                ok, msg = verify_mitigation_output(repo_path, run_dir=run_dir)
                return [f"{'PASS' if ok else 'FAIL'}: {msg}"]
            elif nid == "report":
                f = _output_dir / "threat_model_report.md"
                if f.exists():
                    content = f.read_text()
                    sections = [l for l in content.splitlines() if l.startswith("## ")]
                    return [f"Report written · {len(content.splitlines())} lines · {len(sections)} sections"]
            elif nid == "report_verifier":
                from threatforest.agents.report.verifier import verify_report_output
                ok, msg = verify_report_output(repo_path, run_dir=run_dir)
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
                annotation_traces.push_subgraph_trace(nid, repo_path, run_dir=run_dir)
                if nid == "parallel_verifier":
                    annotation_traces.push_ttp_dataset_items(repo_path, run_dir=run_dir)

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
        "output_dir": str(_output_dir),
        "output_directory": str(_output_dir),
    }
    if failed:
        output["error"] = "; ".join(failed)

    # Flush OTEL spans before returning so traces reach Langfuse
    try:
        from opentelemetry import trace as _trace_api
        _trace_api.get_tracer_provider().force_flush(timeout_millis=10000)
    except Exception:
        pass
    annotation_traces.flush()

    return output
