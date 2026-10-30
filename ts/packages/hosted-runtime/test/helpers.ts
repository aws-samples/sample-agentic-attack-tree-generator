import { createHash } from 'node:crypto';
import {
  ApplicationIdSchema,
  type ApplicationId,
  type UserId,
} from '@threatforest/types';
import {
  InMemoryControlPlane,
  type ApplicationRecord,
  type ControlPlaneScope,
} from '@threatforest/control-plane';
import type {
  ActorIdDeriver,
  AuthenticatedPrincipal,
  Clock,
  StageExecutionContext,
  StageExecutionResult,
  StageExecutor,
} from '../src/contracts.js';
import type { HostedTelemetry } from '../src/telemetry.js';
import { InMemoryArtifactStore } from '../src/artifacts.js';
import { DurableBoundaryExecutor } from '../src/executor.js';
import { VerifiedCognitoPrincipalResolver } from '../src/identity.js';
import { AgentCoreHttpRuntime } from '../src/runtime.js';

export const issuer = 'https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_test';
export const applicationId = ApplicationIdSchema.parse('app_test');

export class ManualClock implements Clock {
  #milliseconds: number;

  constructor(iso = '2026-08-19T12:00:00.000Z') {
    this.#milliseconds = Date.parse(iso);
  }

  now(): Date {
    return new Date(this.#milliseconds);
  }

  advance(milliseconds: number): void {
    this.#milliseconds += milliseconds;
  }
}

export const principalResolver = new VerifiedCognitoPrincipalResolver({
  expectedIssuer: issuer,
});

export async function principal(subject = 'subject-a'): Promise<AuthenticatedPrincipal> {
  return principalResolver.resolve({
    method: 'POST',
    path: '/test',
    context: { verifiedClaims: { sub: subject, iss: issuer } },
  });
}

export function authenticatedContext(subject = 'subject-a'): unknown {
  return { verifiedClaims: { sub: subject, iss: issuer } };
}

export function requestScope(
  ownerId: UserId,
  appId: ApplicationId = applicationId,
): ControlPlaneScope {
  return { owner_id: ownerId, application_id: appId };
}

export async function seedApplication(
  store: InMemoryControlPlane,
  ownerId: UserId,
  appId: ApplicationId = applicationId,
): Promise<ApplicationRecord> {
  const record: ApplicationRecord = {
    schema_version: 1,
    ...requestScope(ownerId, appId),
    name: 'Test application',
    description: null,
    revision: 1,
    created_at: '2026-08-19T12:00:00.000Z',
    updated_at: '2026-08-19T12:00:00.000Z',
  };
  return store.createApplication(record);
}

export function startBody(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    application_id: applicationId,
    source_artifact_ids: ['source_01'],
    threat_artifact_id: null,
    project_path: null,
    threat_file_path: null,
    idempotency_key: 'request-01',
    settings: {
      provider: 'bedrock',
      model_id: 'eu.anthropic.claude-sonnet',
      aws_region: 'eu-west-2',
      model_parameters: { temperature: 0 },
      frameworks: ['STRIDE', 'MITRE ATT&CK', 'PASTA'],
      embeddings_model: 'amazon.titan-embed-text-v2:0',
    },
    ...overrides,
  };
}

export type StageHandler = (
  context: StageExecutionContext,
  call: number,
) => StageExecutionResult | Promise<StageExecutionResult>;

export class ScriptedStageExecutor implements StageExecutor {
  readonly calls: StageExecutionContext[] = [];
  readonly #handlers: Readonly<Record<string, StageHandler>>;

  constructor(handlers: Readonly<Record<string, StageHandler>> = {}) {
    this.#handlers = handlers;
  }

  async execute(context: StageExecutionContext): Promise<StageExecutionResult> {
    this.calls.push(context);
    const call = this.calls.filter((item) => item.stage.id === context.stage.id).length;
    return (this.#handlers[context.stage.id] ?? (() => ({ status: 'completed' })))(context, call);
  }
}

export const deterministicActorDeriver: ActorIdDeriver = {
  async deriveActorId(
    authenticatedPrincipal: AuthenticatedPrincipal,
    appId: ApplicationId,
  ): Promise<string> {
    return `tf_${createHash('sha256')
      .update(`${authenticatedPrincipal.issuer}\0${authenticatedPrincipal.subject}\0${appId}`)
      .digest('base64url')}`;
  },
};

export function runtimeHarness(options: {
  store?: InMemoryControlPlane;
  clock?: ManualClock;
  stageExecutor?: StageExecutor;
  telemetry?: HostedTelemetry;
  stagePlan: ConstructorParameters<typeof DurableBoundaryExecutor>[0]['stagePlan'];
}): {
  store: InMemoryControlPlane;
  clock: ManualClock;
  artifacts: InMemoryArtifactStore;
  executor: DurableBoundaryExecutor;
  runtime: AgentCoreHttpRuntime;
} {
  const store = options.store ?? new InMemoryControlPlane();
  const clock = options.clock ?? new ManualClock();
  const artifacts = new InMemoryArtifactStore(clock);
  const executor = new DurableBoundaryExecutor({
    store,
    artifactStore: artifacts,
    stageExecutor: options.stageExecutor ?? new ScriptedStageExecutor(),
    telemetry: options.telemetry,
    stagePlan: options.stagePlan,
    clock,
    workerId: 'worker-test',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const runtime = new AgentCoreHttpRuntime({
    store,
    executor,
    principalResolver,
    actorIdDeriver: deterministicActorDeriver,
    clock,
    logger: { error: () => {} },
  });
  return { store, clock, artifacts, executor, runtime };
}

export function parseResponse<T>(body: string): T {
  return JSON.parse(body) as T;
}
