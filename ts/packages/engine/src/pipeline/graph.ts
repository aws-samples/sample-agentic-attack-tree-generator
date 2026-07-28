/**
 * Graph orchestrator — port of `src/threatforest/agents/graph.py` build_graph + run_graph.
 *
 * Wires the full pipeline onto the Strands TS Graph:
 *   scanner → scanner_verifier → scanner_review → interviewer → threat →
 *   threat_verifier → threat_review → parallel → parallel_verifier →
 *   probability → report → report_verifier
 * with verifier-gated retry loops.
 *
 * EDGE-SEMANTICS REMODEL (the critical TS-vs-Python difference, see plan gap #3):
 * The Python SDK fires a node when ANY incoming edge is satisfied (OR); the TS
 * SDK fires when ALL are (AND). Python models retry as a second incoming edge on
 * the agent node (verifier→agent on fail) — under AND that would dead-lock the
 * agent waiting for both its entry edge and the retry edge.
 *
 * We avoid that by NOT adding agent-targeted retry edges. Instead each verifier
 * node, in its own `handle()`, owns the retry: it runs the agent up to
 * MAX_RETRIES times until its check passes (or budget is exhausted), then emits
 * a single forward edge. This keeps the graph a DAG (no cycles), is AND-safe,
 * and preserves the Python's observable behaviour (bounded re-runs gated by the
 * deterministic verifier). maxSteps still bounds the whole run as a backstop.
 *
 * HITL: the review/interview nodes pause via an injected interactionFn (see
 * hitl.ts). The orchestrator also registers a BeforeNodeCallEvent hook so a
 * caller that prefers SDK-native interrupts can drive HITL through
 * graph.invoke(InterruptResponseContent[]) resume instead; both paths are wired.
 */
import { Graph, TextBlock } from '@strands-agents/sdk';
import {
  Node,
  AgentNode,
  BeforeNodeCallEvent,
  AfterNodeCallEvent,
  NodeStreamUpdateEvent,
  type MultiAgentInput,
  type MultiAgentState,
  type NodeInputOptions,
  type NodeResultUpdate,
  type MultiAgentStreamEvent,
} from '@strands-agents/sdk/multiagent';

import { LocalFilesystemWorkspace, resolveStateDir, resolveOutputDir } from '../workspace.js';
import { createScannerAgent } from '../agents/scanner.js';
import { createThreatAgent } from '../agents/threat.js';
import { verifyScannerOutput, verifyThreatOutput } from '../verifiers.js';
import { verifyMitigationOutput } from '../agents/mitigation.js';
import { runParallelPipeline } from '../stages/parallel.js';
import { runProbabilityStage } from '../stages/probability-stage.js';
import { runReportGenerator, verifyReportOutput } from '../stages/report.js';
import {
  ScannerReviewNode,
  InterviewerNode,
  ThreatReviewNode,
  createInterviewerAgent,
  type InteractionFn,
} from '../agents/hitl.js';

const MAX_RETRIES = 2;

function textResult(text: string): NodeResultUpdate {
  return { content: [new TextBlock(text)] };
}

/**
 * A node that runs an async function `fn(repoPath, runDir)` and returns its
 * string result. Mirrors the Python FunctionAgent GraphNode wrapper.
 */
class FunctionNode extends Node {
  override readonly type = 'functionNode';
  constructor(
    id: string,
    private readonly fn: (repoPath: string, runDir?: string) => Promise<string> | string,
    private readonly repoPath: string,
    private readonly runDir: string | undefined,
  ) {
    super(id, {});
  }
  override async *handle(
    _input: MultiAgentInput,
    _state: MultiAgentState,
    _options?: NodeInputOptions,
  ): AsyncGenerator<MultiAgentStreamEvent, NodeResultUpdate, undefined> {
    const out = await this.fn(this.repoPath, this.runDir);
    return textResult(String(out ?? 'done'));
  }
}

/**
 * A no-op node used on resume to skip a stage whose output already exists on
 * disk from a prior (paused) run. It returns instantly without re-running the
 * real agent/function. Downstream conditional edges still read the persisted
 * `state/` files, so the pipeline continues correctly from the skipped point.
 * Mirrors the Python `_make_skip_node`.
 */
class SkipNode extends Node {
  override readonly type = 'skipNode';
  constructor(id: string) {
    super(id, {});
  }
  override async *handle(
    _input: MultiAgentInput,
    _state: MultiAgentState,
    _options?: NodeInputOptions,
  ): AsyncGenerator<MultiAgentStreamEvent, NodeResultUpdate, undefined> {
    return textResult(`[skipped] ${this.id} — output already on disk`);
  }
}

/**
 * A verifier node that OWNS the retry loop (the AND-safe remodel of the Python
 * verifier→agent retry edge). It re-runs `rerun()` until `check()` passes or the
 * retry budget is exhausted, then emits forward unconditionally. The downstream
 * conditional edge reads the same verifier result from disk, so a still-failing
 * output simply ends that path (matching Python's terminal behaviour after the
 * retry budget is spent).
 */
class VerifierRetryNode extends Node {
  override readonly type = 'verifierRetryNode';
  constructor(
    id: string,
    private readonly check: () => [boolean, string],
    private readonly rerun: () => Promise<void>,
    private readonly maxRetries = MAX_RETRIES,
  ) {
    super(id, {});
  }
  override async *handle(
    _input: MultiAgentInput,
    _state: MultiAgentState,
    _options?: NodeInputOptions,
  ): AsyncGenerator<MultiAgentStreamEvent, NodeResultUpdate, undefined> {
    let [ok, msg] = this.check();
    let attempts = 0;
    while (!ok && attempts < this.maxRetries) {
      attempts += 1;
      await this.rerun();
      [ok, msg] = this.check();
    }
    return textResult(`${ok ? 'PASS' : 'FAIL'}: ${msg}${attempts ? ` (after ${attempts} retr${attempts === 1 ? 'y' : 'ies'})` : ''}`);
  }
}

/** A node lifecycle tick, surfaced so callers can stream per-stage progress. */
export interface NodeProgressEvent {
  phase: 'start' | 'complete' | 'progress';
  /** The graph node id (e.g. "scanner", "parallel_pipeline"). */
  nodeId: string;
  /**
   * For `phase:'progress'` — an intra-stage fraction in [0,1] so the bar can
   * creep WITHIN a long stage instead of only jumping at node boundaries. For
   * agent nodes this is a soft, monotonic estimate (each LLM round-trip nudges
   * it toward — but never reaching — 1); for the parallel stage it's the real
   * fraction of threats completed.
   */
  fraction?: number;
  /** For `phase:'progress'` — a short human label (e.g. "Threat 3/12"). */
  detail?: string;
}

export interface RunGraphOptions {
  runDir?: string;
  frameworks?: string[] | null;
  interactionFn?: InteractionFn | null;
  /**
   * Optional callback invoked when a graph node starts and completes. The
   * server executor maps these to per-stage ProgressEvents for the WS progress
   * page; without it the page only ever sees the initial "started" event.
   */
  onNodeEvent?: ((e: NodeProgressEvent) => void) | null;
  /**
   * Polled at each node boundary (after every completed node). When it returns
   * true the run stops cleanly at that boundary, leaving all completed-node
   * output on disk so the run can be resumed. This is the cooperative
   * pause/stop mechanism (mirrors the Python executor's `should_interrupt`
   * check at each `multiagent_node_stop`). Without it the graph runs to
   * completion and pause/stop have no mid-run effect.
   */
  shouldInterrupt?: (() => boolean) | null;
  /**
   * Best-effort cancellation forwarded to the SDK (and any cancellation-aware
   * node). Boundary-break via `shouldInterrupt` is the primary mechanism; this
   * lets future signal-aware nodes bail mid-execution.
   */
  cancelSignal?: AbortSignal;
  /**
   * Node ids whose output already exists on disk from a prior (paused) run.
   * Each is replaced with a no-op skip node so a resumed run reuses the
   * persisted `state/` output instead of re-running the stage. Edges and their
   * conditional handlers are unchanged — they read verifier results from disk.
   */
  skipNodes?: string[] | null;
}

export interface RunGraphResult {
  status: 'success' | 'failed' | 'interrupted';
  output_dir: string;
  /**
   * Graph node ids that completed during this run. On an interrupted run this
   * is persisted to `pause_state.json` so a resume can skip them.
   */
  completed_nodes: string[];
  error?: string;
}

/**
 * Build the ThreatForest graph for a repository. The verifier nodes own their
 * retry loops; edges form a DAG. Returns a Strands Graph.
 */
export async function buildGraph(repoPath: string, opts: RunGraphOptions = {}): Promise<Graph> {
  const { runDir, frameworks = null, interactionFn = null, onNodeEvent = null } = opts;
  const skipSet = new Set(opts.skipNodes ?? []);
  const stateDir = resolveStateDir(repoPath, runDir);
  const stateWs = new LocalFilesystemWorkspace(stateDir);

  // Per-threat progress for the parallel stage (the longest). Reports the real
  // fraction of threats finished so the bar advances "Threat 3/12" rather than
  // sitting flat until the whole stage completes.
  const parallelThreatProgress = onNodeEvent
    ? (done: number, total: number): void =>
        onNodeEvent({
          phase: 'progress',
          nodeId: 'parallel_pipeline',
          fraction: total > 0 ? done / total : 0,
          detail: `Analyzing threats (${done}/${total} steps)`,
        })
    : null;

  const scannerAgent = await createScannerAgent(repoPath, runDir);
  const threatAgent = await createThreatAgent(repoPath, runDir);
  const interviewer = createInterviewerAgent(repoPath, runDir);

  // --- LLM agent nodes ---
  const scanner = new AgentNode({ agent: scannerAgent });

  // --- Verifier nodes that own retries (AND-safe; no agent-targeted cycles) ---
  const scannerVerifier = new VerifierRetryNode(
    'scanner_verifier',
    () => verifyScannerOutput(stateWs),
    async () => {
      await scannerAgent.invoke(
        'Analyze this repository and write the project context to the state file.',
      );
    },
  );
  const threatVerifier = new VerifierRetryNode(
    'threat_verifier',
    () => verifyThreatOutput(stateWs),
    async () => {
      await threatAgent.invoke(
        'Read the scanner context and generate threats. Write them to the state file.',
      );
    },
  );
  const parallelVerifier = new VerifierRetryNode(
    'parallel_verifier',
    () => verifyMitigationOutput(repoPath, runDir),
    async () => {
      await runParallelPipeline(repoPath, runDir, frameworks);
    },
  );
  const reportVerifier = new VerifierRetryNode(
    'report_verifier',
    () => verifyReportOutput(repoPath, runDir),
    async () => {
      await runReportGenerator(repoPath, runDir);
    },
  );

  // --- HITL nodes (pause via interactionFn) ---
  const scannerReview = new ScannerReviewNode(stateDir, interactionFn, 'scanner_review');
  const interviewerNode = new InterviewerNode(interviewer, interactionFn, 'interviewer');
  const threatReview = new ThreatReviewNode(stateDir, repoPath, runDir, interactionFn, 'threat_review');

  // --- Function nodes ---
  const threatNode = new AgentNode({ agent: threatAgent });
  const parallelNode = new FunctionNode(
    'parallel_pipeline',
    () => runParallelPipeline(repoPath, runDir, frameworks, parallelThreatProgress),
    repoPath,
    runDir,
  );
  const probability = new FunctionNode('probability', runProbabilityStage, repoPath, runDir);
  const report = new FunctionNode('report', runReportGenerator, repoPath, runDir);

  // Forward edges form a DAG. Verifier→next edges are conditional on the
  // verifier's own check passing (so a terminally-failing verifier ends the
  // path, mirroring Python). Since each verifier node already exhausted its
  // retry budget, this gate is the final pass/fail.
  const scannerOk = () => verifyScannerOutput(stateWs)[0];
  const threatOk = () => verifyThreatOutput(stateWs)[0];
  const parallelOk = () => verifyMitigationOutput(repoPath, runDir)[0];

  // AgentNode ids default to the wrapped agent's id; FunctionNode/VerifierRetryNode
  // ids are explicit. Edges reference nodes by `.id`.
  const realNodes = [
    scanner,
    scannerVerifier,
    scannerReview,
    interviewerNode,
    threatNode,
    threatVerifier,
    threatReview,
    parallelNode,
    parallelVerifier,
    probability,
    report,
    reportVerifier,
  ];

  // On resume, replace any node whose id is in `skipNodes` with a no-op SkipNode
  // (its output already exists in `state/` from the paused run). Edges and the
  // conditional handlers below are unchanged — they read verifier results from
  // disk, so the pipeline resumes correctly from the first not-yet-completed
  // node. A skipped verifier is NOT re-run (its persisted result still gates the
  // downstream conditional edge).
  const nodes = realNodes.map((n) => (skipSet.has(n.id) ? new SkipNode(n.id) : n));

  const realGraph = new Graph({
    id: 'threatforest',
    nodes,
    edges: [
      [scanner.id, scannerVerifier.id],
      { source: scannerVerifier.id, target: scannerReview.id, handler: () => scannerOk() },
      [scannerReview.id, interviewerNode.id],
      [interviewerNode.id, threatNode.id],
      [threatNode.id, threatVerifier.id],
      { source: threatVerifier.id, target: threatReview.id, handler: () => threatOk() },
      [threatReview.id, parallelNode.id],
      [parallelNode.id, parallelVerifier.id],
      { source: parallelVerifier.id, target: probability.id, handler: () => parallelOk() },
      [probability.id, report.id],
      [report.id, reportVerifier.id],
    ],
    sources: [scanner.id],
    maxSteps: 64,
  });

  return realGraph;
}

/**
 * Render a failed node's error for the run summary, including its cause chain.
 *
 * Reporting only `error.message` hid the actual reason for whole classes of
 * failure, because the SDK's outermost message is often a generic wrapper while
 * the diagnosis sits in `.cause`. The motivating case: an HTTP/2 inactivity
 * timeout surfaced purely as "scanner: Stream ended without completing a
 * message" — no mention of a timeout anywhere — which cost a long debugging
 * session to trace back to the transport. `unable to parse tool input JSON` (a
 * swallowed SyntaxError) is wrapped the same way.
 *
 * Depth-capped, and each link is de-duplicated against the text already shown so
 * a wrapper that merely restates its cause does not double up.
 *
 * Exported for tests: the value of this function IS its output string, so it is
 * worth asserting on directly.
 */
export function describeNodeError(error: unknown): string {
  if (!(error instanceof Error)) return 'failed';
  const parts: string[] = [];
  let current: unknown = error;
  for (let depth = 0; current instanceof Error && depth < 4; depth++) {
    const message = current.message.trim();
    // Prefix the name when it carries real signal (TimeoutError, ValidationException)
    // rather than the SDK's generic ModelError/Error.
    const named =
      current.name && !/^(Error|ModelError)$/.test(current.name)
        ? `${current.name}: ${message}`
        : message;
    if (message && !parts.some((p) => p.includes(message))) parts.push(named);
    current = (current as { cause?: unknown }).cause;
  }
  return parts.length > 0 ? parts.join(' <- caused by: ') : 'failed';
}

/**
 * Run the full ThreatForest graph and return a status summary. Port of run_graph
 * (without the rich TUI — the server/CLI render progress from the event stream).
 */
export async function runGraph(repoPath: string, opts: RunGraphOptions = {}): Promise<RunGraphResult> {
  const { setupLangfuseOtel, initSession } = await import('../tracing.js');
  setupLangfuseOtel();
  initSession();

  // Pre-flight: if the pipeline depends on the external Python ML service (the
  // TTP-mapping backend), confirm it's reachable BEFORE running. Otherwise an
  // outage makes every per-threat match throw and be swallowed into an empty
  // result, producing a "complete" run with silently-missing attack paths —
  // dangerous for a security tool. Fail fast with a clear, actionable message.
  const { mlHealthCheck, mlServiceRequired } = await import('../ml/index.js');
  if (mlServiceRequired() && !(await mlHealthCheck())) {
    return {
      status: 'failed',
      output_dir: resolveOutputDir(repoPath, opts.runDir),
      completed_nodes: [],
      error:
        'The Python ML service (TTP-mapping backend) is not reachable. Start it ' +
        '(e.g. `python -m ml_service`) or set TF_USE_PYTHON_ML=0 to use the ' +
        'in-process embedder, then retry. Aborting to avoid an incomplete threat model.',
    };
  }

  const outputDir = resolveOutputDir(repoPath, opts.runDir);
  const graph = await buildGraph(repoPath, opts);

  // Track which nodes completed, so an interrupted run can persist them and a
  // resume can skip them. Recorded on AfterNodeCallEvent (the node-completed
  // boundary — mirrors the Python executor appending on `multiagent_node_stop`).
  // A node interrupted mid-execution never fires AfterNodeCallEvent, so it is
  // correctly NOT in `completed` and will re-run on resume. Skipped nodes (from
  // a prior resume) DO complete instantly and are re-recorded — harmless.
  const completed: string[] = [];
  graph.addHook(AfterNodeCallEvent, (e) => {
    if (!completed.includes(e.nodeId)) completed.push(e.nodeId);
  });

  // Forward node start/complete ticks so the caller can stream per-stage
  // progress. Hooks fire during `stream()`; each carries the node id, which
  // matches the executor's STAGES list 1:1.
  if (opts.onNodeEvent) {
    const emit = opts.onNodeEvent;
    graph.addHook(BeforeNodeCallEvent, (e) => emit({ phase: 'start', nodeId: e.nodeId }));
    graph.addHook(AfterNodeCallEvent, (e) => emit({ phase: 'complete', nodeId: e.nodeId }));

    // Intra-stage motion for AgentNode stages (scanner, threat): each inner LLM
    // round-trip (beforeModelCallEvent) and tool call (beforeToolCallEvent —
    // the scanner spends most of its time reading files) nudges a per-node
    // estimate toward — but never reaching — 100% via an asymptotic curve, so a
    // long stage's bar visibly creeps instead of sitting at 0 until the node
    // completes. FunctionNode stages (parallel_pipeline) emit their own real
    // fractions via the per-threat callback wired in buildGraph.
    const steps = new Map<string, number>();
    graph.addHook(NodeStreamUpdateEvent, (e) => {
      if (e.inner.source !== 'agent') return;
      const innerType = e.inner.event.type;
      if (innerType !== 'beforeModelCallEvent' && innerType !== 'beforeToolCallEvent') return;
      const n = (steps.get(e.nodeId) ?? 0) + 1;
      steps.set(e.nodeId, n);
      // 1 - 0.85^n: gentle asymptote so ~15-20 steps climb steadily toward (but
      // never reach) 100%, leaving the final jump for the node's complete tick.
      const fraction = 1 - Math.pow(0.85, n);
      emit({ phase: 'progress', nodeId: e.nodeId, fraction, detail: `Working (step ${n})` });
    });
  }

  // Consume the graph as a stream so we can stop cleanly at a node boundary when
  // a pause/stop is requested (the Python executor's `should_interrupt` check at
  // each `multiagent_node_stop`). `invoke()` would run the whole graph to
  // completion with no mid-run exit. Completed-node state lives on disk in
  // `state/`, so breaking here leaves a resumable run.
  const shouldInterrupt = opts.shouldInterrupt ?? null;
  const streamOpts = opts.cancelSignal ? { cancelSignal: opts.cancelSignal } : undefined;
  const gen = graph.stream('Run the ThreatForest threat modeling pipeline.', streamOpts);

  let result: Awaited<ReturnType<typeof graph.invoke>>;
  try {
    let next = await gen.next();
    while (!next.done) {
      // Boundary check: after each yielded event, bail if an interrupt was
      // requested. The just-completed nodes are already on disk; the in-flight
      // node (if any) did not fire AfterNodeCallEvent so it re-runs on resume.
      if (shouldInterrupt?.()) {
        // Stop consuming and return immediately. We do NOT `await gen.return()`:
        // the SDK generator may be suspended at an `await` inside a long node
        // (e.g. a Bedrock call), and awaiting `.return()` blocks until that
        // settles — which wedged the run for minutes. Fire-and-forget the
        // cleanup instead; the abandoned node finishes in the background and is
        // GC'd, while completed-node output (already on disk) is what resume
        // uses. (The Python executor likewise just breaks the stream loop.)
        void Promise.resolve(
          gen.return(undefined as unknown as Awaited<ReturnType<typeof graph.invoke>>),
        ).catch(() => {});
        return { status: 'interrupted', output_dir: outputDir, completed_nodes: completed };
      }
      next = await gen.next();
    }
    result = next.value;
  } catch (err) {
    // An external cancelSignal abort surfaces as a throw. ONLY classify a true
    // AbortError as interrupted — NOT any error that happens to coincide with a
    // pause/stop flag being set. The pause flag (`shouldInterrupt`) latches once
    // the user clicks, so a genuine node error (e.g. Bedrock auth failure) that
    // throws while the flag is set must still be reported as a FAILURE, not
    // mislabeled as a resumable pause with the real error swallowed. The
    // boundary-break above already handles the normal (non-throwing) interrupt.
    const isAbort =
      err instanceof Error && (err.name === 'AbortError' || err.name === 'GraphCancelledError');
    if (isAbort && shouldInterrupt?.()) {
      return { status: 'interrupted', output_dir: outputDir, completed_nodes: completed };
    }
    throw err;
  }

  const failed: string[] = [];
  for (const nr of result.results) {
    if (nr.status === 'FAILED') {
      failed.push(`${nr.nodeId}: ${describeNodeError(nr.error)}`);
    }
  }

  return {
    status: result.status === 'COMPLETED' ? 'success' : 'failed',
    output_dir: outputDir,
    completed_nodes: completed,
    ...(failed.length ? { error: failed.join('; ') } : {}),
  };
}
