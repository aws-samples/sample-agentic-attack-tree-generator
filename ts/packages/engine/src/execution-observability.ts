import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { trace, SpanStatusCode, type Attributes } from '@opentelemetry/api';
import {
  Agent, BeforeInvocationEvent, MessageAddedEvent, BeforeModelCallEvent,
  AfterModelCallEvent, BeforeToolCallEvent, AfterToolCallEvent,
  AgentResultEvent, ModelStreamUpdateEvent,
} from '@strands-agents/sdk';
import { boundLogContent, logContent, messageLogContent, type RunLogContent } from '@threatforest/types';

export interface ExecutionObservabilityContext {
  ownerId: string;
  applicationId: string;
  runId: string;
  correlationId: string;
  stage: string;
  attempt: number;
  record?: (attributes: Attributes, error: boolean) => void;
}

const scopes = new AsyncLocalStorage<ExecutionObservabilityContext>();
const sequences = new WeakMap<ExecutionObservabilityContext, number>();

export function withExecutionObservability<T>(scope: ExecutionObservabilityContext, action: () => T): T {
  return scopes.run(Object.freeze({ ...scope }), action);
}

export function executionTraceAttributes(): Attributes {
  const scope = scopes.getStore();
  return scope ? {
    'threatforest.owner.id': scope.ownerId,
    'threatforest.application.id': scope.applicationId,
    'threatforest.run.id': scope.runId,
    'threatforest.run.correlation_id': scope.correlationId,
    'threatforest.stage.id': scope.stage,
    'threatforest.stage.attempt': scope.attempt,
    'threatforest.observability.version': 1,
  } : {};
}

interface ExecutionEvent {
  category: 'agent' | 'model' | 'tool';
  title: string;
  taskId: string;
  taskName: string;
  invocationId: string;
  operationId: string;
  status: 'running' | 'completed' | 'error';
  content: RunLogContent[];
  durationMs?: number;
  attributes?: Attributes;
}

function emit(scope: ExecutionObservabilityContext, event: ExecutionEvent): void {
  // A short span per request/result reaches CloudWatch while the agent is still
  // running. A long parent invocation span is exported only after it finishes.
  try {
    const sequence = (sequences.get(scope) ?? 0) + 1;
    sequences.set(scope, sequence);
    const attributes: Attributes = {
      'threatforest.owner.id': scope.ownerId,
      'threatforest.application.id': scope.applicationId,
      'threatforest.run.id': scope.runId,
      'threatforest.run.correlation_id': scope.correlationId,
      'threatforest.stage.id': scope.stage,
      'threatforest.stage.attempt': scope.attempt,
      'threatforest.execution.id': randomUUID(),
      'threatforest.execution.sequence': sequence,
      'threatforest.execution.category': event.category,
      'threatforest.execution.title': event.title,
      'threatforest.execution.task_id': event.taskId,
      'threatforest.execution.task_name': event.taskName,
      'threatforest.execution.invocation_id': event.invocationId,
      'threatforest.execution.operation_id': event.operationId,
      'threatforest.execution.status': event.status,
      'threatforest.execution.content': JSON.stringify(boundLogContent(event.content)),
      'threatforest.execution.duration_ms': event.durationMs ?? 0,
      ...event.attributes,
    };
    if (scope.record) {
      scope.record(attributes, event.status === 'error');
    } else {
      const span = trace.getTracer('threatforest.execution', '1.0.0').startSpan('threatforest.execution', { attributes });
      span.setStatus({ code: event.status === 'error' ? SpanStatusCode.ERROR : SpanStatusCode.OK });
      span.end();
    }
  } catch {
    // Observability must never change model execution or retry decisions.
  }
}

interface Invocation {
  id: string;
  started: number;
  requestRecorded: boolean;
  model?: { id: string; started: number; usage?: Attributes };
  tools: Map<string, { id: string; started: number }>;
}

export function observeAgent(agent: Agent, taskId: string, taskName: string): Agent {
  const scope = scopes.getStore();
  if (!scope) return agent;
  const invocations = new WeakMap<object, Invocation>();
  const invocation = (state: object): Invocation => {
    let value = invocations.get(state);
    if (!value) {
      value = { id: randomUUID(), started: Date.now(), requestRecorded: false, tools: new Map() };
      invocations.set(state, value);
    }
    return value;
  };
  const send = (state: object, event: Omit<ExecutionEvent, 'taskId' | 'taskName' | 'invocationId'>) =>
    emit(scope, { ...event, taskId, taskName, invocationId: invocation(state).id });

  agent.addHook(BeforeInvocationEvent, (event) => {
    invocations.delete(event.invocationState);
    invocation(event.invocationState);
  });
  agent.addHook(MessageAddedEvent, (event) => {
    const current = invocation(event.invocationState);
    if (current.requestRecorded || event.message.role !== 'user' ||
        !event.message.content.some((block) => block.type === 'textBlock')) return;
    current.requestRecorded = true;
    send(event.invocationState, {
      category: 'agent', title: 'Agent request', operationId: current.id, status: 'running',
      content: messageLogContent(event.message, 'request'),
    });
  });
  agent.addHook(BeforeModelCallEvent, (event) => {
    const current = invocation(event.invocationState);
    current.model = { id: randomUUID(), started: Date.now() };
    send(event.invocationState, {
      category: 'model', title: 'Model request', operationId: current.model.id, status: 'running',
      content: messageLogContent(event.agent.messages, 'request'),
      attributes: { 'gen_ai.request.model': String(event.model.getConfig()['modelId'] ?? 'configured model') },
    });
  });
  agent.addHook(ModelStreamUpdateEvent, (event) => {
    const current = invocation(event.invocationState);
    const update = event.event;
    if (current.model && update.type === 'modelMetadataEvent' && update.usage) {
      current.model.usage = {
        'gen_ai.usage.input_tokens': update.usage.inputTokens,
        'gen_ai.usage.output_tokens': update.usage.outputTokens,
        'gen_ai.usage.total_tokens': update.usage.totalTokens,
      };
    }
  });
  agent.addHook(AfterModelCallEvent, (event) => {
    const call = invocation(event.invocationState).model;
    send(event.invocationState, {
      category: 'model', title: event.error ? 'Model error' : 'Model response',
      operationId: call?.id ?? randomUUID(), status: event.error ? 'error' : 'completed',
      durationMs: call ? Date.now() - call.started : undefined,
      content: event.error ? [logContent('error', event.error.message)] : messageLogContent(event.stopData?.message, 'response'),
      attributes: { ...call?.usage, 'threatforest.model.attempt': event.attemptCount,
        'gen_ai.request.model': String(event.model.getConfig()['modelId'] ?? 'configured model') },
    });
  });
  agent.addHook(BeforeToolCallEvent, (event) => {
    const call = { id: randomUUID(), started: Date.now() };
    invocation(event.invocationState).tools.set(event.toolUse.toolUseId, call);
    send(event.invocationState, {
      category: 'tool', title: 'Tool use', operationId: call.id, status: 'running',
      content: [logContent('tool_input', event.toolUse.input)],
      attributes: { 'gen_ai.tool.name': event.toolUse.name },
    });
  });
  agent.addHook(AfterToolCallEvent, (event) => {
    const call = invocation(event.invocationState).tools.get(event.toolUse.toolUseId);
    send(event.invocationState, {
      category: 'tool', title: 'Tool result', operationId: call?.id ?? randomUUID(),
      status: event.result.status === 'error' ? 'error' : 'completed',
      durationMs: call ? Date.now() - call.started : undefined,
      content: messageLogContent(event.result.content, 'tool_result'),
      attributes: { 'gen_ai.tool.name': event.toolUse.name },
    });
  });
  agent.addHook(AgentResultEvent, (event) => {
    const current = invocation(event.result.invocationState);
    const incomplete = ['cancelled', 'maxTokens', 'limitOutputTokens', 'limitTotalTokens', 'limitTurns',
      'contentFiltered', 'guardrailIntervened', 'refusal', 'modelContextWindowExceeded'].includes(event.result.stopReason);
    send(event.result.invocationState, {
      category: 'agent', title: incomplete ? `Agent stopped (${event.result.stopReason})` : 'Agent response',
      operationId: current.id, status: incomplete ? 'error' : 'completed',
      durationMs: Date.now() - current.started,
      content: messageLogContent(event.result.lastMessage, 'response'),
      attributes: { 'gen_ai.response.finish_reason': event.result.stopReason },
    });
  });
  return agent;
}

export async function observeOperation<T>(
  taskId: string, taskName: string, request: unknown, action: () => Promise<T>,
): Promise<T> {
  const scope = scopes.getStore();
  if (!scope) return action();
  const id = randomUUID();
  const started = Date.now();
  const common = { taskId, taskName, invocationId: id, operationId: id, category: 'tool' as const };
  emit(scope, { ...common, title: 'Tool use', status: 'running', content: [logContent('tool_input', request)] });
  try {
    const result = await action();
    emit(scope, { ...common, title: 'Tool result', status: 'completed', durationMs: Date.now() - started,
      content: [logContent('tool_result', result)] });
    return result;
  } catch (error) {
    emit(scope, { ...common, title: 'Tool error', status: 'error', durationMs: Date.now() - started,
      content: [logContent('error', error instanceof Error ? error.message : String(error))] });
    throw error;
  }
}
