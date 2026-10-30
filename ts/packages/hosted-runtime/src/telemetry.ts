import * as defaultOpenTelemetry from '@opentelemetry/api';
import type { RunSettingsSnapshot } from '@threatforest/types';
import type {
  ControlPlaneScope,
  RunRecord,
} from '@threatforest/control-plane';

export type HostedTelemetryAttributeValue =
  | string
  | number
  | boolean
  | readonly string[]
  | readonly number[]
  | readonly boolean[];

export interface HostedTelemetryEvent {
  spanName: string;
  attributes: Readonly<Record<string, HostedTelemetryAttributeValue>>;
  status: 'ok' | 'error';
}

export interface HostedTelemetry {
  record(event: HostedTelemetryEvent): void;
}

export interface OpenTelemetrySpanLike {
  setAttribute?(
    name: string,
    value: HostedTelemetryAttributeValue,
  ): void;
  setStatus(status: { code: number }): void;
  end(): void;
}

export interface OpenTelemetryApiLike {
  trace: {
    getTracer(
      name: string,
      version?: string,
    ): {
      startSpan(
        name: string,
        options: {
          attributes: Readonly<Record<string, HostedTelemetryAttributeValue>>;
        },
      ): OpenTelemetrySpanLike;
    };
  };
  SpanStatusCode?: {
    OK: number;
    ERROR: number;
  };
}

export interface AgentCoreHostedTelemetryOptions {
  logger?: Pick<Console, 'log'>;
  openTelemetry?: OpenTelemetryApiLike | null;
}

const INSTRUMENTATION_SCOPE =
  'opentelemetry.instrumentation.threatforest.hosted-runtime';
const INSTRUMENTATION_VERSION = '1.0.0';
const EVALUATION_SESSION_PREFIX = 'tf-evaluation-';

function loadOpenTelemetryApi(): OpenTelemetryApiLike | null {
  return defaultOpenTelemetry as OpenTelemetryApiLike;
}

function stringAttribute(
  attributes: Readonly<Record<string, HostedTelemetryAttributeValue>>,
  name: string,
): string | null {
  const value = attributes[name];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function stringListAttribute(
  attributes: Readonly<Record<string, HostedTelemetryAttributeValue>>,
  name: string,
): readonly string[] {
  const value = attributes[name];
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
    ? value
    : [];
}

function numberAttribute(
  attributes: Readonly<Record<string, HostedTelemetryAttributeValue>>,
  name: string,
): number | null {
  const value = attributes[name];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function percentage(value: number | null): string {
  return value === null ? 'not available' : `${Math.round(value * 100)}%`;
}

export function evaluationSessionId(runId: string): string {
  return `${EVALUATION_SESSION_PREFIX}${runId}`;
}

function evaluationAttributes(
  event: HostedTelemetryEvent,
): Readonly<Record<string, HostedTelemetryAttributeValue>> {
  const runId = stringAttribute(event.attributes, 'threatforest.run.id');
  const runCommon: Record<string, HostedTelemetryAttributeValue> = {};
  if (runId !== null) {
    runCommon['session.id'] = runId;
    runCommon['gen_ai.conversation.id'] = runId;
  }

  if (event.spanName === 'threatforest.run.completed') {
    const provider =
      stringAttribute(event.attributes, 'threatforest.model.provider') ??
      'configured provider';
    const model =
      stringAttribute(event.attributes, 'threatforest.model.id') ??
      'configured model';
    const frameworks = stringListAttribute(
      event.attributes,
      'threatforest.ttp.frameworks',
    );
    const input = `Generate an evidence-grounded threat model using ${
      frameworks.length > 0 ? frameworks.join(', ') : 'the configured frameworks'
    } with ${provider}/${model}.`;
    const output =
      'Threat model generation completed and the durable report and quality metrics were published.';
    return {
      ...runCommon,
      'gen_ai.operation.name': 'invoke_agent',
      'gen_ai.task.input': input,
      'gen_ai.task.output': output,
      'agentcore.invocation.user_prompt': input,
      'agentcore.invocation.agent_response': output,
    };
  }

  const stageId = stringAttribute(event.attributes, 'threatforest.stage.id');
  if (event.spanName.startsWith('threatforest.stage.') && stageId !== null) {
    const outcome =
      stringAttribute(event.attributes, 'threatforest.run.outcome') ??
      event.status;
    return {
      ...runCommon,
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': stageId,
      'gen_ai.tool.call.arguments':
        'Execute the durable threat-model pipeline stage with its persisted run context.',
      'gen_ai.tool.call.result': `Stage outcome: ${outcome}.`,
    };
  }

  if (event.spanName === 'threatforest.run.output_quality') {
    const provider =
      stringAttribute(event.attributes, 'threatforest.model.provider') ??
      'configured provider';
    const model =
      stringAttribute(event.attributes, 'threatforest.model.id') ??
      'configured model';
    const frameworks = stringListAttribute(
      event.attributes,
      'threatforest.ttp.frameworks',
    );
    const categories = stringListAttribute(
      event.attributes,
      'threatforest.threat.categories',
    );
    const threatCount =
      numberAttribute(event.attributes, 'threatforest.threat.count') ?? 0;
    const highSeverityCount =
      numberAttribute(
        event.attributes,
        'threatforest.threat.high_severity_count',
      ) ?? 0;
    const gatePassed =
      event.attributes['threatforest.quality.gate_passed'] === true;
    const input = `Generate an evidence-grounded threat model using ${
      frameworks.length > 0 ? frameworks.join(', ') : 'the configured frameworks'
    } with ${provider}/${model}.`;
    const output = [
      `Published ${threatCount} threats, including ${highSeverityCount} high-severity threats`,
      categories.length > 0
        ? `across ${categories.join(', ')}.`
        : 'across the identified threat categories.',
      `TTP decision coverage was ${percentage(
        numberAttribute(
          event.attributes,
          'threatforest.ttp.decision_coverage',
        ),
      )}; accepted mapping coverage was ${percentage(
        numberAttribute(
          event.attributes,
          'threatforest.ttp.accepted_coverage',
        ),
      )}; the explicit abstention rate was ${percentage(
        numberAttribute(event.attributes, 'threatforest.ttp.abstention_rate'),
      )}.`,
      `Mitigation coverage was ${percentage(
        numberAttribute(
          event.attributes,
          'threatforest.mitigation.coverage',
        ),
      )}, with ${percentage(
        numberAttribute(
          event.attributes,
          'threatforest.mitigation.evidence_coverage',
        ),
      )} evidence coverage.`,
      gatePassed
        ? 'All deterministic publication quality gates passed.'
        : 'One or more deterministic publication quality gates require review.',
    ].join(' ');
    const evaluationSession =
      runId === null ? null : evaluationSessionId(runId);
    return {
      ...(evaluationSession === null
        ? runCommon
        : {
            'session.id': evaluationSession,
            'gen_ai.conversation.id': evaluationSession,
            'threatforest.evaluation.session_id': evaluationSession,
          }),
      'gen_ai.operation.name': 'invoke_agent',
      'gen_ai.task.input': input,
      'gen_ai.task.output': output,
      'agentcore.invocation.user_prompt': input,
      'agentcore.invocation.agent_response': output,
      'threatforest.evaluation.ready': true,
    };
  }

  return runCommon;
}

/**
 * Emits custom spans into AgentCore's preconfigured OTEL provider and mirrors
 * each boundary as structured application telemetry when OTEL is unavailable.
 */
export function createAgentCoreHostedTelemetry(
  options: AgentCoreHostedTelemetryOptions = {},
): HostedTelemetry {
  const logger = options.logger ?? console;
  const openTelemetry =
    options.openTelemetry === undefined
      ? loadOpenTelemetryApi()
      : options.openTelemetry;
  const tracer = openTelemetry?.trace.getTracer(
    INSTRUMENTATION_SCOPE,
    INSTRUMENTATION_VERSION,
  );

  return {
    record(event): void {
      const attributes = {
        ...event.attributes,
        ...evaluationAttributes(event),
      };
      try {
        logger.log(
          JSON.stringify({
            level: event.status === 'error' ? 'error' : 'info',
            event: 'threatforest.telemetry',
            instrumentation_scope: INSTRUMENTATION_SCOPE,
            span_name: event.spanName,
            attributes,
          }),
        );
      } catch {
        // Telemetry must never change workflow behavior.
      }

      if (tracer === undefined) {
        return;
      }
      try {
        const span = tracer.startSpan(event.spanName, {
          attributes,
        });
        const sessionId = attributes['session.id'];
        if (typeof sessionId === 'string') {
          // AgentCore injects its Runtime session through OTEL baggage. Apply
          // the evaluation projection after span processors copy that baggage.
          span.setAttribute?.('session.id', sessionId);
          span.setAttribute?.('gen_ai.conversation.id', sessionId);
        }
        span.setStatus({
          code:
            event.status === 'error'
              ? (openTelemetry?.SpanStatusCode?.ERROR ?? 2)
              : (openTelemetry?.SpanStatusCode?.OK ?? 1),
        });
        span.end();
      } catch {
        // The structured record remains available if the OTEL provider fails.
      }
    },
  };
}

export const noopHostedTelemetry: HostedTelemetry = {
  record: () => {},
};

export function runTelemetryAttributes(
  scope: ControlPlaneScope,
  run: RunRecord,
  settings: RunSettingsSnapshot,
  outcome: string,
): Readonly<Record<string, HostedTelemetryAttributeValue>> {
  return {
    'threatforest.application.id': scope.application_id,
    'threatforest.run.id': run.run_id,
    'threatforest.run.correlation_id': run.trace_id,
    'threatforest.model.provider': settings.provider,
    'threatforest.model.id': settings.model_id,
    'threatforest.ttp.frameworks': [...settings.frameworks],
    'threatforest.run.outcome': outcome,
    'gen_ai.provider.name': settings.provider,
    'gen_ai.request.model': settings.model_id,
  };
}
