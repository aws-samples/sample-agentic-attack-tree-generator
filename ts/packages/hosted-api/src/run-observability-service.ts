import { CloudWatchLogsClient, FilterLogEventsCommand, type FilteredLogEvent } from '@aws-sdk/client-cloudwatch-logs';
import {
  RunLogContentSchema, RunLogsResponseSchema, boundLogContent, logContent,
  messageLogContent, parseLogJson, redactLogText, sanitizeLogValue,
  type RunId, type RunLogContent, type RunLogEntry, type RunLogsResponse, type UserId,
} from '@threatforest/types';
import type { RunRecord } from '@threatforest/control-plane';
import { RunService } from './run-service.js';
import { badRequest } from './errors.js';

type Json = Record<string, unknown>;
const COMPLETED_LOG_DELIVERY_ALLOWANCE_MS = 15 * 60_000;
interface SpanEvent { name?: string; attributes?: Json }
interface SpanRecord {
  traceId?: string; spanId?: string; parentSpanId?: string; name?: string;
  startTimeUnixNano?: number | string; endTimeUnixNano?: number | string;
  durationNano?: number | string; attributes?: Json; events?: SpanEvent[];
  status?: { code?: string | number; message?: string };
  logTimestamp?: number;
}
export interface RunLogsQuery { since?: string; until?: string; nextToken?: string }
export interface RunObservabilityServiceOptions {
  runs: Pick<RunService, 'getRecord'>; region: string; logGroupName?: string;
  client?: Pick<CloudWatchLogsClient, 'send'>;
}

export class RunObservabilityService {
  readonly #runs: Pick<RunService, 'getRecord'>;
  readonly #logGroupName: string;
  readonly #client: Pick<CloudWatchLogsClient, 'send'>;
  constructor(options: RunObservabilityServiceOptions) {
    this.#runs = options.runs;
    this.#logGroupName = options.logGroupName ?? 'aws/spans';
    this.#client = options.client ?? new CloudWatchLogsClient({ region: options.region });
  }
  async list(ownerId: UserId, runId: RunId, query: RunLogsQuery = {}): Promise<RunLogsResponse> {
    const run = await this.#runs.getRecord(ownerId, runId);
    const since = query.since === undefined ? Date.parse(run.created_at) : parseTime(query.since, 'since');
    const completedAt = Date.parse(run.completed_at ?? '');
    // Historical views must not scan unrelated traffic indefinitely after the
    // run finished. Keep room for exporter delivery; callers can explicitly
    // widen the window when investigating an unusually delayed event.
    const defaultUntil = Number.isFinite(completedAt)
      ? Math.min(Date.now(), completedAt + COMPLETED_LOG_DELIVERY_ALLOWANCE_MS)
      : Date.now();
    const until = query.until === undefined ? defaultUntil : parseTime(query.until, 'until');
    if (Number.isFinite(since) && since > until) throw badRequest('since must not be later than until.');
    if (query.nextToken && query.nextToken.length > 4096) throw badRequest('Invalid log pagination token.');
    const response = await this.#client.send(new FilterLogEventsCommand({
      logGroupName: this.#logGroupName,
      filterPattern: `"${runId}"`,
      // Content is bounded to 12k characters per event, including every block.
      limit: 100,
      ...(Number.isFinite(since) ? { startTime: since } : {}),
      endTime: until,
      ...(query.nextToken ? { nextToken: query.nextToken } : {}),
    }));
    const spans = (response.events ?? []).map(parseSpan).filter((span): span is SpanRecord => span !== null);
    const byId = new Map(spans.map((span) => [`${span.traceId}:${span.spanId}`, span]));
    const entries = spans.filter((span) => belongsToRun(span, byId, ownerId, runId, run))
      .map((span) => normalizeSpan(runId, span, byId))
      .filter((entry): entry is RunLogEntry => entry !== null);
    return RunLogsResponseSchema.parse({
      run_id: runId,
      entries: [...new Map(entries.map((entry) => [entry.id, entry])).values()]
        .sort((a, b) => a.started_at.localeCompare(b.started_at) ||
          Number(a.details['sequence'] ?? 0) - Number(b.details['sequence'] ?? 0) || a.id.localeCompare(b.id)),
      next_token: response.nextToken ?? null,
      window_end: new Date(until).toISOString(),
      source: 'agentcore_cloudwatch',
    });
  }
}

function parseTime(value: string, name: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || timestamp < 0) throw badRequest(`${name} must be a valid ISO timestamp.`);
  return timestamp;
}
function parseSpan(event: FilteredLogEvent): SpanRecord | null {
  if (typeof event.message !== 'string') return null;
  try {
    const value: unknown = JSON.parse(event.message);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const span = value as SpanRecord;
    if (typeof span.spanId !== 'string' || typeof span.traceId !== 'string' || typeof span.name !== 'string') return null;
    if (span.attributes !== undefined && (!span.attributes || typeof span.attributes !== 'object' || Array.isArray(span.attributes))) return null;
    return {
      ...span, logTimestamp: event.timestamp,
      events: Array.isArray(span.events) ? span.events.filter((entry) => entry && typeof entry === 'object') : [],
    };
  } catch { return null; }
}
function parent(span: SpanRecord, byId: ReadonlyMap<string, SpanRecord>): SpanRecord | undefined {
  return byId.get(`${span.traceId}:${span.parentSpanId}`);
}
function belongsToRun(span: SpanRecord, byId: ReadonlyMap<string, SpanRecord>, ownerId: string, runId: string, run: RunRecord): boolean {
  let current: SpanRecord | undefined = span;
  let matched = false;
  const seen = new Set<string>();
  for (let depth = 0; current && depth < 16; depth++) {
    const key = `${current.traceId}:${current.spanId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    const attrs = current.attributes ?? {};
    const owner = stringAttr(attrs, 'threatforest.owner.id');
    const application = stringAttr(attrs, 'threatforest.application.id');
    const explicitRun = stringAttr(attrs, 'threatforest.run.id');
    if ((owner && owner !== ownerId) || (application && application !== run.application_id) || (explicitRun && explicitRun !== runId)) return false;
    if (explicitRun === runId || stringAttr(attrs, 'session.id') === runId || stringAttr(attrs, 'gen_ai.conversation.id') === runId) matched = true;
    current = parent(current, byId);
  }
  // Text mentioning a run ID is never proof that a span belongs to that run.
  return matched;
}

function normalizeSpan(runId: RunId, span: SpanRecord, byId: ReadonlyMap<string, SpanRecord>): RunLogEntry | null {
  const attrs = span.attributes ?? {};
  const name = span.name ?? '';
  const status = spanStatus(span);
  const stage = resolveStage(span, byId);
  const common = {
    id: `${span.traceId}:${span.spanId}`, run_id: runId,
    trace_id: span.traceId!, span_id: span.spanId!, parent_span_id: span.parentSpanId ?? null,
    stage, status, started_at: nanoToIso(span.startTimeUnixNano, span.logTimestamp),
    completed_at: span.endTimeUnixNano === undefined ? null : nanoToIso(span.endTimeUnixNano, span.logTimestamp),
    duration_ms: nanoToMilliseconds(span.durationNano),
  };
  if (name === 'threatforest.execution') {
    const parsed = RunLogContentSchema.array().safeParse(parseLogJson(attrs['threatforest.execution.content']));
    if (!parsed.success) return null;
    const category = stringAttr(attrs, 'threatforest.execution.category');
    if (category !== 'agent' && category !== 'model' && category !== 'tool') return null;
    const executionStatus = stringAttr(attrs, 'threatforest.execution.status');
    if (!['running', 'completed', 'error'].includes(executionStatus ?? '')) return null;
    const content = boundLogContent(parsed.data);
    return {
      ...common,
      id: stringAttr(attrs, 'threatforest.execution.id') ?? common.id,
      category, status: executionStatus as RunLogEntry['status'],
      title: redactLogText(stringAttr(attrs, 'threatforest.execution.title') ?? 'Execution event'),
      summary: summary(content, stringAttr(attrs, 'gen_ai.tool.name') ?? ''),
      agent_id: stringAttr(attrs, 'threatforest.execution.task_id'),
      agent_name: redactLogText(stringAttr(attrs, 'threatforest.execution.task_name') ?? 'Agent'),
      invocation_id: stringAttr(attrs, 'threatforest.execution.invocation_id'),
      completed_at: executionStatus === 'running' ? null : common.started_at,
      duration_ms: numberAttr(attrs, 'threatforest.execution.duration_ms'),
      content,
      details: details(attrs, { operation_id: attrs['threatforest.execution.operation_id'] }),
    };
  }
  if (name.startsWith('threatforest.stage.')) {
    const action = name.split('.').at(-1) ?? 'activity';
    const failed = action === 'failed' || status === 'error';
    const kind = action === 'started' ? 'request' : failed ? 'error' : 'response';
    return {
      ...common, status: failed ? 'error' : action === 'started' ? 'running' : 'completed',
      category: 'stage', title: `Stage ${action}`, summary: `${humanize(stage ?? 'pipeline')} ${action}.`,
      agent_id: `stage:${stage}`, agent_name: humanize(stage ?? 'Pipeline'),
      content: [logContent(kind, attrs[kind === 'request' ? 'gen_ai.tool.call.arguments' : 'gen_ai.tool.call.result'] ?? `Pipeline stage ${action}.`)],
      details: details(attrs),
    };
  }
  if (name.startsWith('threatforest.hitl.')) return {
    ...common, category: 'hitl', title: 'Human review', summary: humanize(name.split('.').slice(2).join(' ')),
    agent_id: `stage:${stage}`, agent_name: 'Human review',
    content: [logContent('response', { action: attrs['threatforest.hitl.action'], kind: attrs['threatforest.hitl.kind'] })],
    details: details(attrs),
  };
  // New agents emit live request/result events above. Their completed SDK root
  // spans would duplicate the same response and token counts.
  if (attrs['threatforest.observability.version'] === 1) return null;
  const category = name.startsWith('invoke_agent ') ? 'agent' : name.startsWith('execute_tool ') ? 'tool'
    : name === 'chat' || attrs['aws.genai.span_kind'] === 'LLM' ? 'model' : null;
  if (!category) return null;
  const content = legacyContent(span, category);
  if (status === 'error') content.push(logContent('error', span.status?.message ?? 'Execution failed.'));
  const agent = resolveAgent(span, byId);
  const tool = stringAttr(attrs, 'gen_ai.tool.name') ?? name.slice('execute_tool '.length);
  return {
    ...common, category,
    title: category === 'agent' ? 'Agent response' : category === 'tool' ? humanize(tool) : 'Model invocation',
    summary: summary(content, category === 'tool' ? tool : `${category} execution`),
    agent_id: agent.id, agent_name: agent.name, invocation_id: agent.invocation,
    content: boundLogContent(content), details: details(attrs),
  };
}

function legacyContent(span: SpanRecord, category: string): RunLogContent[] {
  const result: RunLogContent[] = [];
  for (const event of Array.isArray(span.events) ? span.events : []) {
    const attrs = event.attributes ?? {};
    if (event.name === 'gen_ai.system.message') continue;
    if (event.name === 'gen_ai.client.inference.operation.details') {
      const input = attrs['gen_ai.input.messages'];
      const output = attrs['gen_ai.output.messages'];
      if (input !== undefined) result.push(...messageLogContent(input, 'request'));
      if (output !== undefined) result.push(...messageLogContent(output, category === 'tool' ? 'tool_result' : 'response'));
    } else if (event.name === 'gen_ai.choice') {
      result.push(...messageLogContent(attrs['message'], category === 'tool' ? 'tool_result' : 'response'));
    } else if (event.name === 'gen_ai.tool.message' && category === 'tool') {
      // A file-write argument is an object containing path AND content, not a
      // message envelope. Keep both and redact before projecting to the UI.
      result.push(logContent('tool_input', attrs['content']));
    } else if (['gen_ai.user.message', 'gen_ai.assistant.message', 'gen_ai.tool.message'].includes(event.name ?? '')) {
      result.push(...messageLogContent(attrs['content'], 'request'));
    }
  }
  return result;
}
function resolveStage(span: SpanRecord, byId: ReadonlyMap<string, SpanRecord>): string | null {
  let current: SpanRecord | undefined = span;
  for (let depth = 0; current && depth < 16; depth++, current = parent(current, byId)) {
    const attrs = current.attributes ?? {};
    const stage = stringAttr(attrs, 'threatforest.stage.id');
    if (stage) return stage;
    const agent = (stringAttr(attrs, 'gen_ai.agent.id') ?? stringAttr(attrs, 'gen_ai.agent.name') ?? '').toLowerCase();
    if (/^(tree|attack.?tree|mitigation|ttp)(?:[- ]|$)/.test(agent)) return 'parallel_pipeline';
    if (['scanner', 'interviewer', 'threat'].includes(agent)) return agent;
  }
  return null;
}
function resolveAgent(span: SpanRecord, byId: ReadonlyMap<string, SpanRecord>): { id: string | null; name: string | null; invocation: string | null } {
  let current: SpanRecord | undefined = span;
  for (let depth = 0; current && depth < 16; depth++, current = parent(current, byId)) {
    const attrs = current.attributes ?? {};
    if (current.name?.startsWith('invoke_agent ')) return {
      id: stringAttr(attrs, 'gen_ai.agent.id') ?? current.spanId ?? null,
      name: redactLogText(stringAttr(attrs, 'gen_ai.agent.name') ?? current.name.slice(13)),
      invocation: current.spanId ?? null,
    };
  }
  return { id: null, name: null, invocation: null };
}
function details(attrs: Json, extra: Json = {}): Json {
  return sanitizeLogValue(Object.fromEntries(Object.entries({
    model_id: attrs['gen_ai.request.model'], tool: attrs['gen_ai.tool.name'],
    input_tokens: attrs['gen_ai.usage.input_tokens'], output_tokens: attrs['gen_ai.usage.output_tokens'],
    total_tokens: attrs['gen_ai.usage.total_tokens'], attempt: attrs['threatforest.stage.attempt'],
    finish_reason: attrs['gen_ai.response.finish_reason'],
    sequence: attrs['threatforest.execution.sequence'],
    model_attempt: attrs['threatforest.model.attempt'], ...extra,
  }).filter(([, value]) => value !== undefined && value !== null))) as Json;
}
function summary(content: readonly RunLogContent[], fallback: string): string {
  const text = content.find((part) => part.kind !== 'reasoning' && part.text)?.text ?? fallback;
  return redactLogText(text).replace(/\s+/g, ' ').slice(0, 240);
}
function spanStatus(span: SpanRecord): RunLogEntry['status'] {
  if (span.status?.code === 'ERROR' || span.status?.code === 2 || span.attributes?.['gen_ai.tool.status'] === 'error') return 'error';
  return span.endTimeUnixNano === undefined ? 'running' : 'completed';
}
function stringAttr(attrs: Json, key: string): string | null { return typeof attrs[key] === 'string' ? attrs[key] as string : null; }
function numberAttr(attrs: Json, key: string): number | null { return typeof attrs[key] === 'number' && Number.isFinite(attrs[key]) && attrs[key] >= 0 ? attrs[key] as number : null; }
function nanoToMilliseconds(value: number | string | undefined): number | null {
  if (value === undefined) return null;
  const number = Number(value) / 1_000_000;
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : null;
}
function nanoToIso(value: number | string | undefined, fallback = 0): string {
  const millis = nanoToMilliseconds(value) ?? fallback;
  return new Date(Math.min(millis, 8.64e15)).toISOString();
}
function humanize(value: string): string { const text = value.replace(/[._-]+/g, ' ').trim(); return text.charAt(0).toUpperCase() + text.slice(1); }
