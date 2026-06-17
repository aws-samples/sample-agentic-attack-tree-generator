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
  phase: 'start' | 'complete';
  /** The graph node id (e.g. "scanner", "parallel_pipeline"). */
  nodeId: string;
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
}

export interface RunGraphResult {
  status: 'success' | 'failed';
  output_dir: string;
  error?: string;
}

/**
 * Build the ThreatForest graph for a repository. The verifier nodes own their
 * retry loops; edges form a DAG. Returns a Strands Graph.
 */
export async function buildGraph(repoPath: string, opts: RunGraphOptions = {}): Promise<Graph> {
  const { runDir, frameworks = null, interactionFn = null } = opts;
  const stateDir = resolveStateDir(repoPath, runDir);
  const stateWs = new LocalFilesystemWorkspace(stateDir);

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
    () => runParallelPipeline(repoPath, runDir, frameworks),
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
  const nodes = [
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
 * Run the full ThreatForest graph and return a status summary. Port of run_graph
 * (without the rich TUI — the server/CLI render progress from the event stream).
 */
export async function runGraph(repoPath: string, opts: RunGraphOptions = {}): Promise<RunGraphResult> {
  const { setupLangfuseOtel, initSession } = await import('../tracing.js');
  setupLangfuseOtel();
  initSession();

  const outputDir = resolveOutputDir(repoPath, opts.runDir);
  const graph = await buildGraph(repoPath, opts);

  // Forward node start/complete ticks so the caller can stream per-stage
  // progress. Hooks fire during `invoke()`; each carries the node id, which
  // matches the executor's STAGES list 1:1.
  if (opts.onNodeEvent) {
    const emit = opts.onNodeEvent;
    graph.addHook(BeforeNodeCallEvent, (e) => emit({ phase: 'start', nodeId: e.nodeId }));
    graph.addHook(AfterNodeCallEvent, (e) => emit({ phase: 'complete', nodeId: e.nodeId }));
  }

  const result = await graph.invoke('Run the ThreatForest threat modeling pipeline.');

  const failed: string[] = [];
  for (const nr of result.results) {
    if (nr.status === 'FAILED') {
      failed.push(`${nr.nodeId}: ${nr.error?.message ?? 'failed'}`);
    }
  }

  return {
    status: result.status === 'COMPLETED' ? 'success' : 'failed',
    output_dir: outputDir,
    ...(failed.length ? { error: failed.join('; ') } : {}),
  };
}
