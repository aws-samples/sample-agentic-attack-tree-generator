/**
 * Human-in-the-loop (HITL) graph nodes.
 *
 * Port of the Python HITL agents:
 *   - `src/threatforest/agents/interviewer/agent.py`   (ScannerReviewNode, InterviewerNode, create_interviewer_agent, ask_user/finalize tools)
 *   - `src/threatforest/agents/interviewer/hook.py`    (InterviewerInterruptHook — see HITL design note below)
 *   - `src/threatforest/agents/interviewer/enricher.py`(enrichScannerContext, applyScannerReviewEdits)
 *   - `src/threatforest/agents/threat_review/agent.py` (ThreatReviewNode)
 *   - `src/threatforest/agents/threat_review/enricher.py`(applyThreatEdits, appendThreatReviewToSummary, buildReviewSummary, diffThreats)
 *
 * =====================================================================================
 * HITL DESIGN NOTE — how interrupts compose with the TS Graph (read before wiring nodes)
 * =====================================================================================
 * The Python pipeline drives HITL two different ways:
 *   1. The deterministic review/interview rounds (ScannerReviewNode, InterviewerNode's
 *      fixed questions, ThreatReviewNode) call a caller-supplied `interaction_fn`
 *      callback with a list of `SimpleInterrupt`s and block on its return value.
 *   2. The interviewer LLM's `ask_user` tool raises a *real* strands interrupt from a
 *      `BeforeToolCallEvent` hook; the node's multi-turn loop then re-feeds the
 *      `interaction_fn` responses back into the agent.
 *
 * In the TS Strands SDK a custom `Node` CANNOT call `event.interrupt()` — that method
 * lives only on `BeforeNodeCallEvent` (a graph-level hook), not inside `Node.handle()`.
 * Per the porting contract we therefore model BOTH HITL paths through a single injected
 * async callback, `InteractionFn`, that mirrors the Python `interaction_fn` exactly:
 *
 *     type InteractionFn = (interrupts: SimpleInterrupt[]) => Promise<InteractionResponse[] | null>
 *
 * Each node holds this callback (injected at construction). When a node needs human
 * input it `await`s `interactionFn(...)`; the callback resolves with the human's
 * responses (or `null` to mean "skipped / dismissed", matching the Python `None`).
 *
 * HOW THE GRAPH PORTER WIRES THIS (the contract the graph relies on):
 *   - The graph registers a `BeforeNodeCallEvent` hook for each HITL node id
 *     ('scanner_review', 'interviewer', 'threat_review'). Inside the hook it calls
 *     `event.interrupt({ name, reason })`, which throws on the first pass (the whole
 *     graph run returns INTERRUPTED with `.interrupts[]`) and, on resume, returns the
 *     human response.
 *   - BUT a single `BeforeNodeCallEvent` fires only ONCE before the node body, whereas
 *     these nodes need MANY interaction rounds (the interviewer loops on "back", the
 *     threat review loops until "proceed", the interviewer LLM may ask_user repeatedly).
 *     So the orchestrator instead supplies an `InteractionFn` that bridges to whatever
 *     transport the host uses (WebSocket prompt to the UI, CLI readline, a queue fed by
 *     `event.interrupt()` responses stored on `state.app`, etc.). The node stays
 *     transport-agnostic: it just awaits the callback.
 *   - `state.app` (a `StateStore`) is the agreed handoff channel: the graph hook writes
 *     each human response under a per-node key and the `InteractionFn` the orchestrator
 *     builds reads it back. Because a node only receives `state` inside `handle()`, the
 *     orchestrator may instead close over `state.app` when it builds the `InteractionFn`
 *     it injects — both are equivalent. This module does not assume a specific channel;
 *     it only requires that `interactionFn` resolve with responses keyed/ordered to
 *     match the interrupts it was given (1:1, same order), exactly like the Python.
 *
 * SEMANTIC GAPS / CAVEATS (flagged explicitly):
 *   - PARITY: the deterministic loops are reproduced 1:1. The interviewer LLM `ask_user`
 *     path differs structurally: Python uses a `BeforeToolCallEvent` hook that raises
 *     `event.interrupt()` and then `cancel_tool`s with the response. Here, the `ask_user`
 *     tool callback itself routes to the SAME `interactionFn` (via a per-agent bridge set
 *     on the node) and returns the human text as the tool result. The OBSERVABLE behavior
 *     is identical (the model asks, the human answers, the model continues), but there is
 *     no separate strands `stop_reason === 'interrupt'` round-trip through the SDK for the
 *     `ask_user` tool — the pause happens inside the tool callback's `await`. This is the
 *     faithful analog given the SDK constraint that tools, not nodes, own tool-level HITL.
 *   - The Python interviewer multi-turn loop keys off `result.stop_reason == "interrupt"`
 *     and `result.interrupts`. With the in-tool bridge above, a single `agent.invoke(...)`
 *     drives the whole conversation (the tool blocks on each question), so we do not need
 *     the explicit resume loop. The "skip" behavior (inject a finalize-now instruction) is
 *     preserved: when `interactionFn` returns `null` for an `ask_user` round, the tool
 *     returns the same skip instruction string the Python injects as the resume response.
 *   - `_rerun_threat_agent_with_feedback` depends on `createThreatAgent` from the (not yet
 *     ported) threat agent module. We dynamic-import `'./threat.js'` and, if it is absent,
 *     degrade exactly like the Python `try/except` around the rerun (log + continue),
 *     so a free-text-feedback round becomes a no-op rather than crashing the loop.
 *
 * STATE-FILE EDITS are ported byte-for-byte (apply_threat_edits, enrich_scanner_context,
 * apply_scanner_review_edits, finalize_interview, append_threat_review_to_summary). All
 * JSON is written via the workspace helper (2-space indent). NOTE: the Python enrichers
 * call `json.dumps(..., indent=2)` with the default `ensure_ascii=True`, whereas the
 * shared workspace writer uses `ensure_ascii=False`. For ASCII content the bytes are
 * identical; the only divergence is non-ASCII characters (escaped `\\uXXXX` in Python vs
 * raw UTF-8 here). We use the workspace writer for consistency with the rest of the port.
 */

import { join } from 'node:path';

import { Agent, TextBlock, tool, type ContentBlock } from '@strands-agents/sdk';
import {
  Node,
  Status,
  type MultiAgentInput,
  type MultiAgentState,
  type MultiAgentStreamEvent,
  type NodeConfig,
  type NodeInputOptions,
  type NodeResultUpdate,
} from '@strands-agents/sdk/multiagent';
import { z } from 'zod';

import { config } from '../config.js';
import { createModel } from '../providers.js';
import { makeRetryStrategy } from '../retry.js';
import { makeSandboxedFileRead } from '../tools/sandboxed-file.js';
import { traceAttrs } from '../tracing.js';
import { LocalFilesystemWorkspace, resolveStateDir } from '../workspace.js';
import { INTERVIEWER_PROMPT } from './interviewer.prompt.js';

// ---------------------------------------------------------------------------
// SimpleInterrupt / InteractionFn — the HITL contract (see design note above)
// ---------------------------------------------------------------------------

/**
 * Lightweight interrupt for non-LLM interaction rounds. Mirrors the Python
 * `SimpleInterrupt` dataclass used by ScannerReviewNode / InterviewerNode /
 * ThreatReviewNode so a single `interactionFn` handles both these and any real
 * strands interrupts the orchestrator forwards.
 */
export interface SimpleInterrupt {
  id: string;
  reason: Record<string, unknown>;
}

/**
 * One human response to one interrupt. Shape matches the Python WS payload the
 * nodes read: `responses[i].interruptResponse.response`.
 */
export interface InteractionResponse {
  interruptResponse?: { interruptId?: string; response?: unknown };
}

/**
 * Caller-supplied async callback that routes interrupts to the human and
 * resolves with their responses (1:1, same order), or `null` when the human
 * skips/dismisses — the analog of Python `interaction_fn(...)` returning `None`.
 */
export type InteractionFn = (
  interrupts: SimpleInterrupt[],
) => Promise<InteractionResponse[] | null> | InteractionResponse[] | null;

// ---------------------------------------------------------------------------
// Fixed interview questions (identical every run) — port of agent.py constants
// ---------------------------------------------------------------------------

/**
 * Data sensitivity and main CIA risk focus used to be asked here but are now
 * captured up front by BusinessContext when the user creates the application,
 * so the interviewer no longer re-asks them.
 */
const FIXED_QUESTIONS = ['Is this system in production, early design, or early development?'];

const BACK_SENTINEL = '__back__';

// ---------------------------------------------------------------------------
// threat_review constants — port of threat_review/agent.py + enricher.py
// ---------------------------------------------------------------------------

const QUESTIONS = [
  'Do these threats make sense for your application?',
  'Do you want to change the priority of any of them?',
  'Are there any false positives?',
  'Are there any new threats you think we should add?',
];

const ALLOWED_PRIORITIES = new Set(['critical', 'high', 'medium', 'low']);

// ===========================================================================
// enricher.py — interviewer
// ===========================================================================

/**
 * Enrich scanner_context.json with interview results. Faithful port of
 * `enricher.enrich_scanner_context`:
 *   - stores user_context / interviewer_confidence / interviewer_summary
 *   - list fields (auth_mechanisms, services, compliance_requirements): append uniques
 *   - scalar fields (data_sensitivity, deployment_model, industry): set only if unset
 */
export function enrichScannerContext(
  workspace: LocalFilesystemWorkspace,
  key: string,
  additionalContext: Record<string, unknown>,
  confidence: string,
  summary: string,
): void {
  const ctx = workspace.readJson<Record<string, unknown>>(key);

  // Store raw interview results.
  ctx['user_context'] = additionalContext;
  ctx['interviewer_confidence'] = confidence;
  ctx['interviewer_summary'] = summary;

  // Merge list fields: append unique items.
  const listFields = ['auth_mechanisms', 'services', 'compliance_requirements'];
  for (const field of listFields) {
    if (field in additionalContext) {
      const existingArr = (ctx[field] as unknown[] | undefined) ?? [];
      const existing = new Set(existingArr);
      const incoming = (additionalContext[field] as unknown[] | undefined) ?? [];
      for (const item of incoming) {
        if (!existing.has(item)) {
          if (!Array.isArray(ctx[field])) ctx[field] = [];
          (ctx[field] as unknown[]).push(item);
          // NOTE: Python uses a single `existing` set snapshotted before the loop, so
          // duplicate items WITHIN `incoming` are both appended. Match that exactly by
          // not adding to `existing` here.
        }
      }
    }
  }

  // Merge scalar fields only if not already set.
  const scalarFields = ['data_sensitivity', 'deployment_model', 'industry'];
  for (const field of scalarFields) {
    if (field in additionalContext && !ctx[field]) {
      ctx[field] = additionalContext[field];
    }
  }

  workspace.writeJson(key, ctx);
}

/**
 * Apply user edits from the scanner review to scanner_context.json. Faithful
 * port of `enricher.apply_scanner_review_edits`: list fields replaced entirely,
 * scalar fields overwritten, then `scanner_review_applied = True`.
 */
export function applyScannerReviewEdits(
  workspace: LocalFilesystemWorkspace,
  key: string,
  edits: Record<string, unknown>,
): void {
  const ctx = workspace.readJson<Record<string, unknown>>(key);

  const editableFields = [
    'files_analyzed',
    'industry',
    'services',
    'auth_mechanisms',
    'cloud_provider',
    'tech_stack',
    'data_sensitivity',
    'compliance_requirements',
  ];

  for (const field of editableFields) {
    if (field in edits) {
      ctx[field] = edits[field];
    }
  }

  ctx['scanner_review_applied'] = true;
  workspace.writeJson(key, ctx);
}

// ===========================================================================
// enricher.py — threat_review
// ===========================================================================

type ThreatEdit = { priority?: unknown; remove?: unknown };

/**
 * Apply structured edits to threats.json. Faithful port of
 * `threat_review.enricher.apply_threat_edits`:
 *   - per-threat `remove: truthy` drops the threat
 *   - per-threat `priority` overwrites when it's an allowed value (lowercased)
 */
export function applyThreatEdits(
  workspace: LocalFilesystemWorkspace,
  key: string,
  edits: Record<string, ThreatEdit>,
): void {
  const data = workspace.readJson<{ threats?: Array<Record<string, unknown>> }>(key);
  const threats = data.threats ?? [];

  const removeIds = new Set<string>();
  for (const [tid, e] of Object.entries(edits)) {
    if (e && e.remove) removeIds.add(tid);
  }

  const kept: Array<Record<string, unknown>> = [];
  for (const t of threats) {
    const tid = t['id'] as string | undefined;
    if (tid !== undefined && removeIds.has(tid)) continue;
    const patch = (tid !== undefined ? edits[tid] : undefined) ?? {};
    const newPrio = patch.priority;
    if (newPrio && ALLOWED_PRIORITIES.has(String(newPrio).toLowerCase())) {
      t['priority'] = String(newPrio).toLowerCase();
    }
    kept.push(t);
  }

  data.threats = kept;
  workspace.writeJson(key, data);
}

/**
 * Build a short natural-language recap of the review loop. Faithful port of
 * `threat_review.enricher.build_review_summary` (line-for-line, same pluralization).
 */
export function buildReviewSummary(args: {
  rounds: number;
  feedbacks: string[];
  addedThreatIds: string[];
  removedThreatIds: string[];
  priorityChanges: Array<{ id: string; from: string; to: string }>;
  skipped: boolean;
}): string {
  const { rounds, feedbacks, addedThreatIds, removedThreatIds, priorityChanges, skipped } = args;

  if (skipped) {
    return 'User reviewed threats, no changes requested.';
  }

  const lines: string[] = [];
  lines.push(`User reviewed threats across ${rounds} round${rounds !== 1 ? 's' : ''}.`);

  for (const change of priorityChanges) {
    lines.push(`- Changed priority of ${change.id} from ${change.from} to ${change.to}.`);
  }

  for (const tid of removedThreatIds) {
    lines.push(`- Removed ${tid} (flagged as false positive or irrelevant).`);
  }

  if (addedThreatIds.length > 0) {
    const joined = addedThreatIds.join(', ');
    lines.push(
      `- Added ${addedThreatIds.length} threat${addedThreatIds.length !== 1 ? 's' : ''} ` +
        `based on feedback: ${joined}.`,
    );
  }

  const nonemptyFeedback = feedbacks.map((f) => f.trim()).filter((f) => f.length > 0);
  if (nonemptyFeedback.length > 0) {
    const joinedFeedback = nonemptyFeedback.join(' | ');
    lines.push(`Free-text feedback: "${joinedFeedback}"`);
  }

  return lines.join('\n');
}

/**
 * Merge the threat-review summary into `interviewer_summary`. Faithful port of
 * `threat_review.enricher.append_threat_review_to_summary` (wraps prior plain
 * summary under `## Context validation`, appends `## Threat statement review`).
 */
export function appendThreatReviewToSummary(
  workspace: LocalFilesystemWorkspace,
  key: string,
  threatReviewSummary: string,
): void {
  const ctx = workspace.exists(key) ? workspace.readJson<Record<string, unknown>>(key) : {};
  let existing = String(ctx['interviewer_summary'] ?? '').trim();

  if (existing && !existing.replace(/^\s+/, '').startsWith('## ')) {
    existing = `## Context validation\n${existing}`;
  } else if (!existing) {
    // No prior interview summary (interview skipped entirely) — still include an
    // explicit Context validation section for symmetry.
    existing = '## Context validation\nContext validation was skipped.';
  }

  const combined =
    existing + '\n\n' + '## Threat statement review\n' + threatReviewSummary.trim();
  ctx['interviewer_summary'] = combined;
  workspace.writeJson(key, ctx);
}

/** Compute a diff between two threat lists. Port of `enricher.diff_threats`. */
export function diffThreats(
  before: Array<Record<string, unknown>>,
  after: Array<Record<string, unknown>>,
): { added: string[]; removed: string[]; priorityChanges: Array<{ id: string; from: string; to: string }> } {
  const beforeById = new Map<string, Record<string, unknown>>();
  for (const t of before) beforeById.set(t['id'] as string, t);
  const afterById = new Map<string, Record<string, unknown>>();
  for (const t of after) afterById.set(t['id'] as string, t);

  const added: string[] = [];
  for (const tid of afterById.keys()) if (!beforeById.has(tid)) added.push(tid);
  const removed: string[] = [];
  for (const tid of beforeById.keys()) if (!afterById.has(tid)) removed.push(tid);

  const priorityChanges: Array<{ id: string; from: string; to: string }> = [];
  for (const [tid, tAfter] of afterById.entries()) {
    const tBefore = beforeById.get(tid);
    if (!tBefore) continue;
    const pBefore = String(tBefore['priority'] ?? '').toLowerCase();
    const pAfter = String(tAfter['priority'] ?? '').toLowerCase();
    if (pBefore && pAfter && pBefore !== pAfter) {
      priorityChanges.push({ id: tid, from: pBefore, to: pAfter });
    }
  }

  return { added, removed, priorityChanges };
}

// ===========================================================================
// Shared node helpers
// ===========================================================================

/** Build the single-text-block `NodeResultUpdate` the framework wraps into a NodeResult. */
function textResult(text: string): NodeResultUpdate {
  const content: ContentBlock[] = [new TextBlock(text)];
  return { status: Status.COMPLETED, content };
}

/** Coerce an `InteractionFn` return (sync or async) into a promise. */
async function callInteraction(
  fn: InteractionFn,
  interrupts: SimpleInterrupt[],
): Promise<InteractionResponse[] | null> {
  return await Promise.resolve(fn(interrupts));
}

/** Pull `responses[0].interruptResponse.response` as a string (Python `.get(..., "")`). */
function firstResponseText(responses: InteractionResponse[]): string {
  const r = responses[0]?.interruptResponse?.response;
  return typeof r === 'string' ? r : r === undefined || r === null ? '' : String(r);
}

/** JSON.parse that returns the parsed dict only when it's a plain object, else null. */
function tryParseEditsDict(raw: string): Record<string, unknown> | null {
  try {
    const obj: unknown = JSON.parse(raw);
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      return obj as Record<string, unknown>;
    }
  } catch {
    /* JSONDecodeError / TypeError → treat as plain-text confirmation */
  }
  return null;
}

/**
 * The scanner_data sub-payload sent to the review UI. Shared by both review
 * surfaces. Uses `dict.get(key, default)` semantics (default only when the key
 * is absent) to match the Python `ctx.get(...)` calls byte-for-byte.
 */
function scannerDataPayload(ctx: Record<string, unknown>): Record<string, unknown> {
  const g = (key: string, dflt: unknown): unknown => (key in ctx ? ctx[key] : dflt);
  return {
    files_analyzed: g('files_analyzed', []),
    industry: g('industry', ''),
    services: g('services', []),
    auth_mechanisms: g('auth_mechanisms', []),
    // Send as original strings — frontend splits into tokens for editing.
    cloud_provider: g('cloud_provider', ''),
    tech_stack: g('tech_stack', ''),
    data_sensitivity: g('data_sensitivity', ''),
    compliance_requirements: g('compliance_requirements', []),
    main_cia_risk: g('main_cia_risk', ''),
  };
}

// ===========================================================================
// interviewer agent — create_interviewer_agent + tools
// ===========================================================================

/**
 * Bridge that lets the interviewer LLM's `ask_user` tool route to the node's
 * injected `interactionFn`. Set on the node before each `agent.invoke(...)`.
 * See the HITL design note: tools (not custom nodes) own tool-level HITL in the
 * TS SDK, so the tool callback awaits this instead of raising `event.interrupt()`.
 */
interface AskUserBridge {
  fn: InteractionFn | null;
}

const AskUserInputSchema = z.object({
  message: z
    .string()
    .describe(
      'A SHORT 1-2 sentence intro. No preamble or flattery. Just state what gaps you need filled.',
    ),
  questions: z
    .array(z.string())
    .describe('A list of 2-5 separate question strings. Each question is its own list item.'),
  context_summary: z
    .record(z.string(), z.unknown())
    .describe('Summary of what the scanner already found, for user context.'),
});

const FinalizeInputSchema = z.object({
  confidence: z
    .string()
    .describe('Assessment of context completeness — "high", "medium", or "low".'),
  additional_context: z
    .record(z.string(), z.unknown())
    .describe('Dict of user-provided context to merge into scanner_context.'),
  summary: z.string().describe('Brief summary of what was learned in the interview.'),
});

/**
 * Skip-response text injected when the user skips an `ask_user` round. Copied
 * verbatim from the Python InterviewerNode resume-skip path so the model gets
 * the same instruction whether the skip happens at the tool or the resume seam.
 */
const ASK_USER_SKIP_INSTRUCTION =
  'The user chose to skip the interview. Call finalize_interview immediately with ' +
  "confidence='low', an empty additional_context dict, and a summary noting the " +
  'interview was skipped.';

/**
 * Create an interviewer agent scoped to the given repository.
 *
 * Returns the `Agent` plus the `AskUserBridge` the caller (InterviewerNode) wires
 * to its `interactionFn`. Mirrors `create_interviewer_agent`: same tools
 * (sandboxed read, ask_user, finalize_interview), same model temperature (0.3),
 * same system prompt + appended Context section, same trace attributes.
 */
export function createInterviewerAgent(
  repoPath: string,
  runDir?: string,
): { agent: Promise<Agent>; bridge: AskUserBridge; workspace: LocalFilesystemWorkspace; stateKey: string } {
  const stateDir = resolveStateDir(repoPath, runDir);
  const workspace = new LocalFilesystemWorkspace(stateDir);
  const stateKey = 'scanner_context.json';
  const stateFile = join(stateDir, stateKey);

  // Bridge mutated by the node before each invoke so ask_user reaches the human.
  const bridge: AskUserBridge = { fn: null };

  const askUser = tool({
    name: 'ask_user',
    description:
      'Ask the user questions about their application to fill gaps in the scanner context. ' +
      'This pauses the agent and routes the questions to the user; when they respond the agent resumes.',
    inputSchema: AskUserInputSchema,
    callback: async (input: z.infer<typeof AskUserInputSchema>): Promise<string> => {
      // Tool-level HITL: route to the node's interactionFn (see HITL design note).
      // Analog of the Python InterviewerInterruptHook raising event.interrupt() and
      // then cancel_tool-ing with `f"User response: {response}"`.
      if (bridge.fn === null) {
        // No interaction wired (parity with the Python tool body that only runs if
        // the hook didn't fire) — return the same fallback string.
        return 'No response received — the interrupt hook may not be configured.';
      }
      const interrupt: SimpleInterrupt = {
        id: 'interviewer_question',
        reason: {
          message: input.message ?? '',
          questions: input.questions ?? [],
          context_summary: input.context_summary ?? {},
        },
      };
      const responses = await callInteraction(bridge.fn, [interrupt]);
      if (responses === null) {
        // User skipped — inject the same finalize-now instruction the Python uses.
        return `User response: ${ASK_USER_SKIP_INSTRUCTION}`;
      }
      const responseText = firstResponseText(responses);
      return `User response: ${responseText}`;
    },
  });

  const finalizeInterview = tool({
    name: 'finalize_interview',
    description:
      'Finalize the interview and write enriched context to scanner_context.json.',
    inputSchema: FinalizeInputSchema,
    callback: (input: z.infer<typeof FinalizeInputSchema>): string => {
      enrichScannerContext(
        workspace,
        stateKey,
        input.additional_context ?? {},
        input.confidence,
        input.summary,
      );
      return `Interview finalized. Confidence: ${input.confidence}. Context written to ${stateFile}.`;
    },
  });

  const systemPrompt =
    INTERVIEWER_PROMPT +
    `\n\n## Context\n` +
    `- Scanner context file: \`${stateFile}\`\n` +
    `- Repository path: \`${repoPath}\`\n`;

  const agent = (async (): Promise<Agent> => {
    const model = await createModel(config, { temperature: 0.3 });
    return new Agent({
      model,
      systemPrompt,
      tools: [makeSandboxedFileRead([repoPath, stateDir]), askUser, finalizeInterview],
      printer: false,
      retryStrategy: makeRetryStrategy(),
      traceAttributes: traceAttrs('interviewer'),
    });
  })();

  return { agent, bridge, workspace, stateKey };
}

// ===========================================================================
// ScannerReviewNode
// ===========================================================================

/**
 * Presents scanner findings to the user for confirmation/editing. Port of
 * `interviewer.agent.ScannerReviewNode`: reads scanner_context.json, sends a
 * `scanner_review` interrupt via interactionFn, applies any user edits.
 */
export class ScannerReviewNode extends Node {
  override readonly type = 'scannerReviewNode';
  private readonly workspace: LocalFilesystemWorkspace;
  private readonly interactionFn: InteractionFn | null;
  private readonly stateKey = 'scanner_context.json';

  constructor(stateDir: string, interactionFn: InteractionFn | null, nodeId = 'scanner_review') {
    const config: NodeConfig = { description: 'HITL: confirm/edit scanner findings' };
    super(nodeId, config);
    this.workspace = new LocalFilesystemWorkspace(stateDir);
    this.interactionFn = interactionFn;
  }

  async *handle(
    _input: MultiAgentInput,
    _state: MultiAgentState,
    _options?: NodeInputOptions,
  ): AsyncGenerator<MultiAgentStreamEvent, NodeResultUpdate, undefined> {
    if (this.interactionFn === null || !this.workspace.exists(this.stateKey)) {
      return textResult('Scanner review skipped (no interaction_fn).');
    }

    const ctx = this.workspace.readJson<Record<string, unknown>>(this.stateKey);

    const reviewPayload: Record<string, unknown> = {
      phase: 'scanner_review',
      message: "Here's what the scanner found. Please confirm or edit before we continue.",
      scanner_data: scannerDataPayload(ctx),
    };

    const interrupt: SimpleInterrupt = { id: 'scanner-review', reason: reviewPayload };
    const responses = await callInteraction(this.interactionFn, [interrupt]);

    if (responses !== null) {
      // Parse user response — expect JSON with edits or plain "confirmed".
      const raw = firstResponseText(responses);
      const edits = tryParseEditsDict(raw);
      if (edits && !edits['confirmed_only']) {
        applyScannerReviewEdits(this.workspace, this.stateKey, edits);
      }
    }

    return textResult('Scanner review complete.');
  }
}

// ===========================================================================
// InterviewerNode
// ===========================================================================

/**
 * Graph node that runs the interviewer with interrupt-based HITL. Port of
 * `interviewer.agent.InterviewerNode`:
 *   Phase 1: send FIXED_QUESTIONS via interactionFn (no LLM). User can go "back"
 *            to re-edit scanner findings (BACK_SENTINEL loop).
 *   Phase 2: feed answers + scanner context to the LLM for follow-ups. The LLM's
 *            ask_user tool routes back through interactionFn via the bridge.
 */
export class InterviewerNode extends Node {
  override readonly type = 'interviewerNode';
  private readonly agentP: Promise<Agent>;
  private readonly bridge: AskUserBridge;
  private readonly interactionFn: InteractionFn | null;
  private readonly workspace: LocalFilesystemWorkspace;
  private readonly stateKey = 'scanner_context.json';

  constructor(
    created: { agent: Promise<Agent>; bridge: AskUserBridge; workspace: LocalFilesystemWorkspace },
    interactionFn: InteractionFn | null,
    nodeId = 'interviewer',
  ) {
    super(nodeId, { description: 'HITL: standard questions + LLM follow-ups' });
    this.agentP = created.agent;
    this.bridge = created.bridge;
    this.interactionFn = interactionFn;
    // Reuse the workspace from createInterviewerAgent so the node's
    // scanner-review-back edits and the agent's finalize/enrich writes share the
    // same root (the run's state dir).
    this.workspace = created.workspace;
  }

  /** Build a scanner-review interrupt from current scanner_context.json (the "back" surface). */
  private buildScannerReviewInterrupt(): SimpleInterrupt {
    const ctx = this.workspace.exists(this.stateKey)
      ? this.workspace.readJson<Record<string, unknown>>(this.stateKey)
      : {};
    return {
      id: 'scanner-review-back',
      reason: {
        phase: 'scanner_review',
        message: 'Edit your scanner findings, then continue.',
        scanner_data: scannerDataPayload(ctx),
      },
    };
  }

  async *handle(
    _input: MultiAgentInput,
    _state: MultiAgentState,
    _options?: NodeInputOptions,
  ): AsyncGenerator<MultiAgentStreamEvent, NodeResultUpdate, undefined> {
    if (this.interactionFn === null) {
      const resultStr = await this.runSkip();
      return textResult(resultStr);
    }

    let userText = '';

    // Phase 1: Fixed questions with back-to-scanner-review loop.
    for (;;) {
      const fixedInterrupt: SimpleInterrupt = {
        id: 'fixed-questions',
        reason: {
          phase: 'interviewer',
          message: 'A few standard questions before we begin threat modeling.',
          questions: FIXED_QUESTIONS,
        },
      };
      const fixedResponses = await callInteraction(this.interactionFn, [fixedInterrupt]);

      if (fixedResponses === null) {
        const resultStr = await this.runSkip();
        return textResult(resultStr);
      }

      userText = firstResponseText(fixedResponses);

      if (userText === BACK_SENTINEL) {
        // User wants to go back to scanner review.
        const reviewInterrupt = this.buildScannerReviewInterrupt();
        const reviewResponses = await callInteraction(this.interactionFn, [reviewInterrupt]);
        if (reviewResponses !== null) {
          const raw = firstResponseText(reviewResponses);
          const edits = tryParseEditsDict(raw);
          if (edits && !edits['confirmed_only']) {
            applyScannerReviewEdits(this.workspace, this.stateKey, edits);
          }
        }
        continue; // Loop back to show fixed questions again.
      }

      break; // Got real answers, proceed to phase 2.
    }

    // Phase 2: Feed answers + scanner context to the LLM for follow-ups.
    // The ask_user tool routes through interactionFn via the bridge, so a single
    // invoke drives the whole multi-turn follow-up conversation (see HITL note).
    const agent = await this.agentP;
    this.bridge.fn = this.interactionFn;
    let resultStr: string;
    try {
      const result = await agent.invoke(
        `The user answered the standard interview questions as follows:\n\n` +
          `${userText}\n\n` +
          'Read the scanner context file. Based on these answers and any remaining gaps, ' +
          'either ask targeted follow-up questions using ask_user, or call finalize_interview ' +
          'if you have enough context.',
      );
      resultStr = String(result);
    } finally {
      this.bridge.fn = null;
    }

    return textResult(resultStr);
  }

  /** Skip interview — write low confidence to scanner context (port of `_run_skip`). */
  private async runSkip(): Promise<string> {
    const agent = await this.agentP;
    this.bridge.fn = this.interactionFn; // finalize_interview needs no human input
    try {
      const result = await agent.invoke(
        'The interview is being skipped. Call finalize_interview immediately ' +
          "with confidence='low', an empty additional_context dict, and a summary " +
          'noting the interview was skipped.',
      );
      return String(result);
    } finally {
      this.bridge.fn = null;
    }
  }
}

// ===========================================================================
// ThreatReviewNode
// ===========================================================================

/** Read the current threats list (safe if missing/malformed). Port of `_threats_payload`. */
function threatsPayload(workspace: LocalFilesystemWorkspace): Array<Record<string, unknown>> {
  if (!workspace.exists('threats.json')) return [];
  let data: { threats?: Array<Record<string, unknown>> };
  try {
    data = workspace.readJson<{ threats?: Array<Record<string, unknown>> }>('threats.json');
  } catch {
    return [];
  }
  return data.threats ?? [];
}

/** Trim threat fields to what the review UI needs. Port of `_summarize_threat_for_ui`. */
function summarizeThreatForUi(t: Record<string, unknown>): Record<string, unknown> {
  // Python uses dict.get(key, default): the default applies ONLY when the key is
  // absent. A present-but-null value is kept (str(None) -> "none"), so we branch on
  // `in` rather than `?? default` to match that exactly.
  const priority = 'priority' in t ? t['priority'] : 'medium';
  return {
    id: 'id' in t ? t['id'] : '',
    title: 'title' in t ? t['title'] : '',
    description: 'description' in t ? t['description'] : '',
    priority: String(priority).toLowerCase(),
    affected_components: 'affected_components' in t ? t['affected_components'] : [],
  };
}

/** Parse the user's WS response as JSON; fall back to a proceed. Port of `_safe_parse`. */
function safeParse(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { action: 'proceed' };
  }
  try {
    const obj: unknown = JSON.parse(raw);
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      return obj as Record<string, unknown>;
    }
  } catch {
    /* JSONDecodeError → proceed */
  }
  return { action: 'proceed' };
}

/**
 * HITL threat review. Loops until the user proceeds. Port of
 * `threat_review.agent.ThreatReviewNode`:
 *   - shows current threats + 4 guided questions each round
 *   - applies structured edits (priority/remove) to threats.json
 *   - on free-text feedback, re-invokes the threat agent with a revision prompt
 *   - on exit, appends a structured recap to scanner_context.json:interviewer_summary
 */
export class ThreatReviewNode extends Node {
  override readonly type = 'threatReviewNode';
  private readonly workspace: LocalFilesystemWorkspace;
  private readonly repoPath: string;
  private readonly runDir: string | undefined;
  private readonly interactionFn: InteractionFn | null;

  constructor(
    stateDir: string,
    repoPath: string,
    runDir: string | undefined,
    interactionFn: InteractionFn | null,
    nodeId = 'threat_review',
  ) {
    super(nodeId, { description: 'HITL: review generated threats, loop until proceed' });
    this.workspace = new LocalFilesystemWorkspace(stateDir);
    this.repoPath = repoPath;
    this.runDir = runDir;
    this.interactionFn = interactionFn;
  }

  async *handle(
    _input: MultiAgentInput,
    _state: MultiAgentState,
    _options?: NodeInputOptions,
  ): AsyncGenerator<MultiAgentStreamEvent, NodeResultUpdate, undefined> {
    const threatsKey = 'threats.json';
    const scannerKey = 'scanner_context.json';

    if (this.interactionFn === null || !this.workspace.exists(threatsKey)) {
      return textResult('Threat review skipped (no interaction_fn).');
    }

    let rounds = 0;
    const feedbacks: string[] = [];
    // copy.deepcopy of the initial threats so the final diff is against round 0.
    const initialThreats = structuredClone(threatsPayload(this.workspace));
    let anyActionTaken = false;

    for (;;) {
      rounds += 1;
      const current = threatsPayload(this.workspace);
      const payload: Record<string, unknown> = {
        phase: 'threat_review',
        message:
          'Review the generated threats. Change priorities, remove false ' +
          "positives, or describe any additional threats you'd like added.",
        questions: QUESTIONS,
        threats: current.map((t) => summarizeThreatForUi(t)),
      };

      const interrupt: SimpleInterrupt = { id: `threat-review-${rounds}`, reason: payload };
      const responses = await callInteraction(this.interactionFn, [interrupt]);

      if (responses === null) {
        // User dismissed/skipped — treat as proceed with no action.
        break;
      }

      const raw = responses[0]?.interruptResponse?.response;
      const parsed = safeParse(raw);
      const action = (parsed['action'] as string | undefined) ?? 'proceed';

      if (action === 'proceed') {
        // If this is the very first round and nothing was submitted, fall through
        // with anyActionTaken=false so the summary marks the stage as skipped.
        break;
      }

      // action == "apply" — structured edits + optional feedback.
      const edits = (parsed['edits'] as Record<string, ThreatEdit> | undefined) ?? {};
      const feedback = String(parsed['feedback'] ?? '').trim();

      if (Object.keys(edits).length > 0) {
        applyThreatEdits(this.workspace, threatsKey, edits);
        anyActionTaken = true;
      }

      if (feedback) {
        feedbacks.push(feedback);
        anyActionTaken = true;
        try {
          await this.rerunThreatAgentWithFeedback(feedback);
        } catch (exc) {
          // Don't crash the loop on agent failure — next iteration just re-shows
          // the threats as they were.
          // eslint-disable-next-line no-console
          console.log(`[threat_review] revision agent failed: ${String(exc)}`);
        }
      }

      // Loop continues — next iteration fetches fresh threats.
    }

    // Build and persist the summary.
    const finalThreats = threatsPayload(this.workspace);
    const diff = diffThreats(initialThreats, finalThreats);
    const reviewSummary = buildReviewSummary({
      rounds,
      feedbacks,
      addedThreatIds: diff.added,
      removedThreatIds: diff.removed,
      priorityChanges: diff.priorityChanges,
      skipped: !anyActionTaken,
    });
    try {
      appendThreatReviewToSummary(this.workspace, scannerKey, reviewSummary);
    } catch (exc) {
      // eslint-disable-next-line no-console
      console.log(`[threat_review] failed to persist summary: ${String(exc)}`);
    }

    return textResult('Threat review complete.');
  }

  /**
   * Re-invoke the threat agent to revise threats.json based on feedback. Port of
   * `_rerun_threat_agent_with_feedback`.
   *
   * CAVEAT: depends on the (not-yet-ported) threat agent module. We dynamic-import
   * `'./threat.js'` and look for `createThreatAgent`; if it's absent we throw a
   * clear error which the caller's try/catch swallows (parity with Python: the
   * loop continues, re-showing the unchanged threats), so the feedback round
   * becomes a no-op rather than crashing the pipeline.
   */
  private async rerunThreatAgentWithFeedback(feedback: string): Promise<void> {
    const mod = (await import('./threat.js').catch(() => null)) as
      | { createThreatAgent?: (repoPath: string, runDir?: string) => Agent | Promise<Agent> }
      | null;
    if (!mod || typeof mod.createThreatAgent !== 'function') {
      throw new Error(
        'createThreatAgent not available (threat agent not yet ported); skipping revision round.',
      );
    }
    const agent = await mod.createThreatAgent(this.repoPath, this.runDir);
    const prompt =
      'The user has reviewed your previously generated threats and provided ' +
      'feedback. Read the existing threats.json file (it already contains ' +
      'your previous output), then revise the threat list according to the ' +
      "user's feedback below. Preserve each threat's existing priority " +
      '(unless the user explicitly asks to change it) and keep existing ' +
      'threats unless the user explicitly asks to remove them. Add any new ' +
      'threats the user describes. Use the next available TS00X id for ' +
      'added threats. Write the complete revised threat list back to the ' +
      'state file.\n\n' +
      `User feedback:\n${feedback}`;
    await agent.invoke(prompt);
  }
}
