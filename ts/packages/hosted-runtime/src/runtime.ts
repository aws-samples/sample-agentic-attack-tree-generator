import {
  ApplicationIdSchema,
  ArtifactIdSchema,
  HitlResponseSchema,
  InteractionIdSchema,
  RunIdSchema,
  type ApplicationId,
} from '@threatforest/types';
import {
  ControlPlaneError,
  type ControlPlaneScope,
  type ControlPlaneStore,
} from '@threatforest/control-plane';
import type {
  ActorIdDeriver,
  AuthenticatedPrincipal,
  BoundaryResult,
  Clock,
  PrincipalResolver,
  RunSettingsInput,
  RuntimeHttpRequest,
  RuntimeHttpResponse,
  StartRunInput,
} from './contracts.js';
import { systemClock } from './contracts.js';
import {
  DurableBoundaryExecutor,
  StaleDispatchError,
  hitlInteractionId,
} from './executor.js';
import type { ApprovedFeedbackMemory } from './memory.js';
import { isRecord } from './util.js';

export class RequestValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RequestValidationError';
  }
}

export interface AgentCoreRuntimeOptions {
  store: ControlPlaneStore;
  executor: DurableBoundaryExecutor;
  principalResolver: PrincipalResolver;
  actorIdDeriver: ActorIdDeriver;
  clock?: Clock;
  logger?: Pick<Console, 'error'>;
  memory?: ApprovedFeedbackMemory;
  shutdownSignal?: AbortSignal;
}

function json(statusCode: number, value: unknown): RuntimeHttpResponse {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
    body: JSON.stringify(value),
  };
}

function objectBody(value: unknown): Record<string, unknown> {
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value) as unknown;
    } catch {
      throw new RequestValidationError('request body must be valid JSON');
    }
  }
  if (!isRecord(value)) {
    throw new RequestValidationError('request body must be a JSON object');
  }
  if ('owner_id' in value || 'actor_id' in value) {
    throw new RequestValidationError('owner_id and actor_id are derived from authentication');
  }
  return value;
}

function assertAllowed(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label = 'request',
): void {
  const allowedSet = new Set(allowed);
  const unexpected = Object.keys(value).filter((key) => !allowedSet.has(key));
  if (unexpected.length > 0) {
    throw new RequestValidationError(
      `${label} contains unsupported fields: ${unexpected.sort().join(', ')}`,
    );
  }
}

function requiredString(
  value: Record<string, unknown>,
  key: string,
  maxLength = 512,
): string {
  const item = value[key];
  if (typeof item !== 'string' || item.length === 0 || item.length > maxLength) {
    throw new RequestValidationError(`${key} must be a non-empty string`);
  }
  return item;
}

function nullableString(
  value: Record<string, unknown>,
  key: string,
  maxLength = 4096,
): string | null {
  const item = value[key];
  if (item === undefined || item === null) {
    return null;
  }
  if (typeof item !== 'string' || item.length > maxLength) {
    throw new RequestValidationError(`${key} must be a string or null`);
  }
  return item;
}

function optionalStringArray(
  value: Record<string, unknown>,
  key: string,
  maxItems = 10_000,
): string[] {
  const item = value[key];
  if (item === undefined) {
    return [];
  }
  if (
    !Array.isArray(item) ||
    item.length > maxItems ||
    item.some((entry) => typeof entry !== 'string')
  ) {
    throw new RequestValidationError(`${key} must be an array of strings`);
  }
  return item as string[];
}

function parseSettings(value: unknown): RunSettingsInput {
  if (!isRecord(value)) {
    throw new RequestValidationError('settings must be an object');
  }
  assertAllowed(
    value,
    [
      'provider',
      'model_id',
      'aws_region',
      'model_parameters',
      'frameworks',
      'embeddings_model',
    ],
    'settings',
  );
  const parameters = value['model_parameters'];
  if (!isRecord(parameters)) {
    throw new RequestValidationError('model_parameters must be an object');
  }
  for (const parameter of Object.values(parameters)) {
    if (
      typeof parameter !== 'string' &&
      typeof parameter !== 'number' &&
      typeof parameter !== 'boolean'
    ) {
      throw new RequestValidationError('model_parameters values must be scalar');
    }
  }
  const frameworks = optionalStringArray(value, 'frameworks', 128);
  if (frameworks.length === 0 || frameworks.some((framework) => framework.length > 128)) {
    throw new RequestValidationError('frameworks must contain at least one valid framework');
  }
  return {
    provider: requiredString(value, 'provider', 128),
    model_id: requiredString(value, 'model_id', 512),
    aws_region: nullableString(value, 'aws_region', 64),
    model_parameters: parameters as Record<string, string | number | boolean>,
    frameworks,
    embeddings_model: requiredString(value, 'embeddings_model', 512),
  };
}

function parseStart(body: Record<string, unknown>, headers: RuntimeHttpRequest['headers']): StartRunInput {
  assertAllowed(body, [
    'application_id',
    'source_artifact_ids',
    'threat_artifact_id',
    'project_path',
    'threat_file_path',
    'settings',
    'idempotency_key',
  ]);
  const sourceIds = optionalStringArray(body, 'source_artifact_ids').map((id) =>
    ArtifactIdSchema.parse(id),
  );
  const projectPath = nullableString(body, 'project_path');
  if (sourceIds.length === 0 && (projectPath === null || projectPath.trim().length === 0)) {
    throw new RequestValidationError('source_artifact_ids or project_path is required');
  }
  let headerKey: string | undefined;
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() === 'idempotency-key') {
      headerKey = Array.isArray(value) ? value[0] : value;
    }
  }
  const bodyKey = body['idempotency_key'];
  if (bodyKey !== undefined && typeof bodyKey !== 'string') {
    throw new RequestValidationError('idempotency_key must be a string');
  }
  const idempotencyKey = headerKey ?? bodyKey;
  if (
    typeof idempotencyKey !== 'string' ||
    idempotencyKey.length === 0 ||
    idempotencyKey.length > 256
  ) {
    throw new RequestValidationError('an idempotency key of at most 256 characters is required');
  }
  return {
    applicationId: ApplicationIdSchema.parse(requiredString(body, 'application_id', 128)),
    sourceArtifactIds: sourceIds,
    threatArtifactId:
      body['threat_artifact_id'] === undefined || body['threat_artifact_id'] === null
        ? null
        : ArtifactIdSchema.parse(body['threat_artifact_id']),
    projectPath,
    threatFilePath: nullableString(body, 'threat_file_path'),
    settings: parseSettings(body['settings']),
    idempotencyKey,
  };
}

function scope(ownerId: ControlPlaneScope['owner_id'], applicationId: ApplicationId): ControlPlaneScope {
  return { owner_id: ownerId, application_id: applicationId };
}

function responseStatus(boundary: string): number {
  return boundary === 'awaiting_input' || boundary === 'busy' ? 202 : 200;
}

function errorStatus(error: unknown): number {
  if (error instanceof StaleDispatchError) {
    return 409;
  }
  if (
    error instanceof RequestValidationError ||
    (error instanceof Error && error.name === 'ZodError')
  ) {
    return 400;
  }
  if (error instanceof ControlPlaneError) {
    if (error.code === 'not_found') {
      return 404;
    }
    if (error.code === 'invalid_input') {
      return 400;
    }
    return 409;
  }
  if (error instanceof Error && error.name === 'AuthenticationError') {
    return 401;
  }
  return 500;
}

function authenticationDiagnostic(
  request: RuntimeHttpRequest,
): Readonly<Record<string, unknown>> {
  const headerNames = Object.keys(request.headers ?? {})
    .map((name) => name.toLowerCase())
    .sort();
  const names = new Set(headerNames);
  return {
    level: 'warn',
    event: 'runtime_authentication_failed',
    method: request.method.toUpperCase(),
    path: request.path,
    header_names: headerNames,
    runtime_user_header_present: names.has(
      'x-amzn-bedrock-agentcore-runtime-user-id',
    ),
    runtime_principal_header_present: names.has(
      'x-amzn-bedrock-agentcore-runtime-custom-userid',
    ),
    authorization_header_present: names.has('authorization'),
  };
}

export class AgentCoreHttpRuntime {
  readonly #store: ControlPlaneStore;
  readonly #executor: DurableBoundaryExecutor;
  readonly #principalResolver: PrincipalResolver;
  readonly #actorIdDeriver: ActorIdDeriver;
  readonly #clock: Clock;
  readonly #logger: Pick<Console, 'error'>;
  readonly #memory: ApprovedFeedbackMemory | null;
  readonly #shutdownSignal: AbortSignal;
  readonly #tasks = new Map<string, Promise<BoundaryResult>>();

  get busy(): boolean { return this.#tasks.size > 0; }

  /** Shutdown and integration tests can drain work without losing rejections. */
  async drain(): Promise<void> { await Promise.allSettled(this.#tasks.values()); }

  constructor(options: AgentCoreRuntimeOptions) {
    this.#store = options.store;
    this.#executor = options.executor;
    this.#principalResolver = options.principalResolver;
    this.#actorIdDeriver = options.actorIdDeriver;
    this.#clock = options.clock ?? systemClock;
    this.#logger = options.logger ?? console;
    this.#memory = options.memory ?? null;
    this.#shutdownSignal = options.shutdownSignal ?? new AbortController().signal;
  }

  async handle(request: RuntimeHttpRequest): Promise<RuntimeHttpResponse> {
    try {
      if (request.method.toUpperCase() === 'GET' && request.path === '/ping') {
        return json(200, { status: this.busy ? 'HealthyBusy' : 'Healthy' });
      }
      if (request.method.toUpperCase() !== 'POST') {
        return json(405, { error: 'method_not_allowed' });
      }
      const principal = await this.#principalResolver.resolve(request);
      const body = objectBody(request.body);
      if (request.path === '/invocations') {
        const operation = body['operation'];
        if (operation === 'execute_run') {
          return await this.#executeRun(principal.userId, principal, body);
        }
        if (operation === 'control_run') {
          return await this.#controlRun(principal.userId, principal, body);
        }
        throw new RequestValidationError('operation is not supported');
      }
      switch (request.path) {
        case '/invocations/start-run':
          return await this.#startRun(principal.userId, principal, body, request.headers);
        case '/invocations/get-run':
          return await this.#getRun(principal.userId, principal, body);
        case '/invocations/respond-hitl':
          return await this.#respondHitl(principal.userId, principal, body);
        case '/invocations/list-events':
          return await this.#listEvents(principal.userId, principal, body);
        default:
          return json(404, { error: 'route_not_found' });
      }
    } catch (error) {
      const status = errorStatus(error);
      if (status === 401) {
        this.#logger.error(JSON.stringify(authenticationDiagnostic(request)));
      } else if (status === 500) {
        this.#logger.error('AgentCore runtime request failed', error);
      }
      return json(status, {
        error:
          error instanceof StaleDispatchError
            ? error.code
            : error instanceof ControlPlaneError
            ? error.code
            : error instanceof Error
              ? error.name
              : 'InternalError',
        message: status === 500 ? 'internal runtime error' : String((error as Error).message),
      });
    }
  }

  async #executeRun(
    ownerId: ControlPlaneScope['owner_id'],
    principal: AuthenticatedPrincipal,
    body: Record<string, unknown>,
  ): Promise<RuntimeHttpResponse> {
    assertAllowed(body, [
      'operation',
      'application_id',
      'run_id',
      'dispatch_generation',
    ]);
    const applicationId = ApplicationIdSchema.parse(
      requiredString(body, 'application_id', 128),
    );
    const runId = RunIdSchema.parse(requiredString(body, 'run_id', 128));
    const dispatchGeneration = body['dispatch_generation'];
    if (
      !Number.isSafeInteger(dispatchGeneration) ||
      (dispatchGeneration as number) < 1
    ) {
      throw new RequestValidationError(
        'dispatch_generation must be a positive integer',
      );
    }
    const requestScope = scope(ownerId, applicationId);
    const run = await this.#store.getRun(requestScope, runId);
    if (run === null) {
      throw new ControlPlaneError('not_found', 'run was not found');
    }
    if (run.revision !== dispatchGeneration) {
      throw new StaleDispatchError(
        dispatchGeneration as number,
        run.revision,
      );
    }
    const actorId = await this.#actorIdDeriver.deriveActorId(
      principal,
      applicationId,
    );
    const taskKey = `${ownerId}/${applicationId}/${runId}`;
    if (this.#tasks.has(taskKey)) {
      return json(202, { boundary: 'busy', run, actor_id: actorId, interaction: null });
    }
    if (['completed', 'failed', 'cancelled'].includes(run.status)) {
      return json(200, {
        boundary: run.status === 'completed' ? 'completed' : 'failed',
        run, actor_id: actorId, interaction: null,
      });
    }
    if (run.status === 'awaiting_input' &&
        (await this.#store.getRunControl(requestScope, runId))?.action === 'pause') {
      return json(202, { boundary: 'awaiting_input', run, actor_id: actorId, interaction: null });
    }
    if (run.current_stage_id !== null) {
      const interaction = await this.#store.getHitlRequest(
        requestScope,
        hitlInteractionId(runId, run.current_stage_id),
      );
      if (interaction !== null && interaction.run_id === runId) {
        const response = await this.#store.getHitlResponse(
          requestScope,
          interaction.interaction_id,
          interaction.revision,
        );
        if (run.status === 'awaiting_input' && response === null) {
          return json(202, { boundary: 'awaiting_input', run, actor_id: actorId, interaction });
        }
        if (response !== null) {
          await this.#recordApprovedFeedback({
            actorId,
            applicationId,
            runId,
            request: interaction,
            response,
          });
        }
      }
    }
    this.#shutdownSignal.throwIfAborted();
    if (this.#tasks.has(taskKey)) {
      return json(202, { boundary: 'busy', run, actor_id: actorId, interaction: null });
    }
    // The existing fenced executor/checkpoints remain the source of truth.
    // AgentCore keeps this session active while /ping reports HealthyBusy.
    const task = this.#executor.runUntilBoundary(
      requestScope,
      runId,
      actorId,
      this.#shutdownSignal,
      dispatchGeneration as number,
    ).finally(() => { this.#tasks.delete(taskKey); });
    this.#tasks.set(taskKey, task);
    void task.catch(error => this.#logger.error('Background run interrupted; durable checkpoint is available for retry', error));
    return json(202, { boundary: 'busy', run, actor_id: actorId, interaction: null });
  }

  async #controlRun(
    ownerId: ControlPlaneScope['owner_id'],
    principal: Awaited<ReturnType<PrincipalResolver['resolve']>>,
    body: Record<string, unknown>,
  ): Promise<RuntimeHttpResponse> {
    assertAllowed(body, ['operation', 'application_id', 'run_id', 'action']);
    const applicationId = ApplicationIdSchema.parse(
      requiredString(body, 'application_id', 128),
    );
    const runId = RunIdSchema.parse(requiredString(body, 'run_id', 128));
    const action = body['action'];
    if (action !== 'pause' && action !== 'stop') {
      throw new RequestValidationError('action must be pause or stop');
    }
    const requestScope = scope(ownerId, applicationId);
    const actorId = await this.#actorIdDeriver.deriveActorId(
      principal,
      applicationId,
    );
    const result = await this.#executor.requestControl(
      requestScope,
      runId,
      actorId,
      action,
    );
    return json(responseStatus(result.boundary), result);
  }

  async #startRun(
    ownerId: ControlPlaneScope['owner_id'],
    principal: Awaited<ReturnType<PrincipalResolver['resolve']>>,
    body: Record<string, unknown>,
    headers: RuntimeHttpRequest['headers'],
  ): Promise<RuntimeHttpResponse> {
    const input = parseStart(body, headers);
    const requestScope = scope(ownerId, input.applicationId);
    const actorId = await this.#actorIdDeriver.deriveActorId(principal, input.applicationId);
    const result = await this.#executor.startRun(
      requestScope,
      input,
      actorId,
      this.#shutdownSignal,
    );
    return json(responseStatus(result.boundary), result);
  }

  async #getRun(
    ownerId: ControlPlaneScope['owner_id'],
    principal: Awaited<ReturnType<PrincipalResolver['resolve']>>,
    body: Record<string, unknown>,
  ): Promise<RuntimeHttpResponse> {
    assertAllowed(body, ['application_id', 'run_id']);
    const applicationId = ApplicationIdSchema.parse(requiredString(body, 'application_id', 128));
    const runId = RunIdSchema.parse(requiredString(body, 'run_id', 128));
    const requestScope = scope(ownerId, applicationId);
    const run = await this.#store.getRun(requestScope, runId);
    if (run === null) {
      throw new ControlPlaneError('not_found', 'run was not found');
    }
    const [settings, checkpoints, events, pendingInteractions, actorId] = await Promise.all([
      this.#store.getRunSettingsSnapshot(requestScope, runId),
      this.#store.listCheckpoints(requestScope, runId),
      this.#store.listEvents(requestScope, runId),
      this.#store.listPendingHitl(requestScope, runId),
      this.#actorIdDeriver.deriveActorId(principal, applicationId),
    ]);
    return json(200, {
      run,
      settings,
      checkpoints,
      events,
      pending_interactions: pendingInteractions,
      actor_id: actorId,
    });
  }

  async #respondHitl(
    ownerId: ControlPlaneScope['owner_id'],
    principal: Awaited<ReturnType<PrincipalResolver['resolve']>>,
    body: Record<string, unknown>,
  ): Promise<RuntimeHttpResponse> {
    assertAllowed(body, [
      'application_id',
      'run_id',
      'interaction_id',
      'revision',
      'action',
      'text',
    ]);
    const applicationId = ApplicationIdSchema.parse(requiredString(body, 'application_id', 128));
    const runId = RunIdSchema.parse(requiredString(body, 'run_id', 128));
    const id = InteractionIdSchema.parse(requiredString(body, 'interaction_id', 128));
    const revision = body['revision'];
    const action = body['action'];
    if (!Number.isInteger(revision) || (revision as number) < 1) {
      throw new RequestValidationError('revision must be a positive integer');
    }
    if (action !== 'submit' && action !== 'skip') {
      throw new RequestValidationError('action must be submit or skip');
    }
    const text = nullableString(body, 'text', 1_000_000);
    const requestScope = scope(ownerId, applicationId);
    const run = await this.#store.getRun(requestScope, runId);
    if (run === null) {
      throw new ControlPlaneError('not_found', 'run was not found');
    }
    const currentRequest = await this.#store.getHitlRequest(requestScope, id);
    if (currentRequest === null || currentRequest.run_id !== runId) {
      throw new ControlPlaneError('not_found', 'HITL request was not found');
    }
    if (currentRequest.revision !== revision) {
      throw new ControlPlaneError(
        'stale_revision',
        `HITL revision ${String(revision)} is no longer current`,
      );
    }
    const response = HitlResponseSchema.parse({
      schema_version: 1,
      ...requestScope,
      interaction_id: id,
      run_id: runId,
      revision,
      action,
      text,
      submitted_at: this.#clock.now().toISOString(),
    });
    const existing = await this.#store.getHitlResponse(requestScope, id, revision as number);
    if (existing === null) {
      await this.#store.respondToHitl(response);
    } else if (
      existing.run_id !== response.run_id ||
      existing.action !== response.action ||
      existing.text !== response.text
    ) {
      throw new ControlPlaneError('conflict', 'HITL response already differs');
    }
    const actorId = await this.#actorIdDeriver.deriveActorId(principal, applicationId);
    await this.#recordApprovedFeedback({
      actorId,
      applicationId,
      runId,
      request: currentRequest,
      response,
    });
    const result = await this.#executor.runUntilBoundary(
      requestScope,
      runId,
      actorId,
      this.#shutdownSignal,
    );
    return json(responseStatus(result.boundary), result);
  }

  async #listEvents(
    ownerId: ControlPlaneScope['owner_id'],
    principal: Awaited<ReturnType<PrincipalResolver['resolve']>>,
    body: Record<string, unknown>,
  ): Promise<RuntimeHttpResponse> {
    assertAllowed(body, ['application_id', 'run_id', 'after_sequence']);
    const applicationId = ApplicationIdSchema.parse(requiredString(body, 'application_id', 128));
    const runId = RunIdSchema.parse(requiredString(body, 'run_id', 128));
    const after = body['after_sequence'] ?? -1;
    if (!Number.isInteger(after) || (after as number) < -1) {
      throw new RequestValidationError('after_sequence must be an integer at least -1');
    }
    const requestScope = scope(ownerId, applicationId);
    if ((await this.#store.getRun(requestScope, runId)) === null) {
      throw new ControlPlaneError('not_found', 'run was not found');
    }
    const [events, actorId] = await Promise.all([
      this.#store.listEvents(requestScope, runId, after as number),
      this.#actorIdDeriver.deriveActorId(principal, applicationId),
    ]);
    return json(200, { events, actor_id: actorId });
  }

  async #recordApprovedFeedback(
    input: Parameters<ApprovedFeedbackMemory['recordApprovedFeedback']>[0],
  ): Promise<void> {
    if (this.#memory === null) {
      return;
    }
    try {
      await this.#memory.recordApprovedFeedback(input);
    } catch (error) {
      this.#logger.error(
        JSON.stringify({
          level: 'error',
          event: 'agentcore_memory_write_failed',
          operation: 'record_approved_feedback',
          application_id: input.applicationId,
          run_id: input.runId,
          interaction_id: input.request.interaction_id,
          revision: input.response.revision,
        }),
        error,
      );
    }
  }
}
