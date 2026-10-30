import { randomUUID } from 'node:crypto';
import {
  ApplicationIdSchema,
  ArtifactIdSchema,
  HitlRequestSchema,
  IdempotencyRecordSchema,
  InteractionIdSchema,
  RunIdSchema,
  RunSettingsSnapshotSchema,
  StageCheckpointSchema,
  type ArtifactRef,
  type HitlRequest,
  type HitlResponse,
  type Lease,
  type RunId,
  type RunSettingsSnapshot,
  type StageCheckpoint,
} from '@threatforest/types';
import {
  ControlPlaneError,
  conflict,
  leaseLost,
  runLeaseResourceId,
  type ControlPlaneScope,
  type ControlPlaneStore,
  type LeaseGuard,
  type RunRecord,
  type RunStatus,
} from '@threatforest/control-plane';
import type {
  BoundaryResult,
  DurableBoundaryExecutorOptions,
  StageDefinition,
  StageExecutionResult,
  StartRunInput,
} from './contracts.js';
import { systemClock, type Clock } from './contracts.js';
import { THREATFOREST_STAGE_PLAN, validateStagePlan } from './stage-plan.js';
import {
  noopHostedTelemetry,
  runTelemetryAttributes,
  type HostedTelemetry,
  type HostedTelemetryAttributeValue,
} from './telemetry.js';
import { canonicalJson, compactError, sha256 } from './util.js';

const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1_000;

function plusMilliseconds(date: Date, milliseconds: number): string {
  return new Date(date.getTime() + milliseconds).toISOString();
}

function sameScope(left: ControlPlaneScope, right: ControlPlaneScope): boolean {
  return (
    left.owner_id === right.owner_id && left.application_id === right.application_id
  );
}

export function hitlInteractionId(
  runId: RunId,
  stageId: string,
): ReturnType<typeof InteractionIdSchema.parse> {
  return InteractionIdSchema.parse(`hitl_${sha256(`${runId}\0${stageId}`).slice(0, 48)}`);
}

function stageIdempotencyKey(runId: RunId, stage: StageDefinition): string {
  return `stage:${runId}:${stage.id}:v${stage.version}`;
}

function eventId(runId: RunId, type: string, stage: string | null, discriminator: string): string {
  return `evt_${sha256(`${runId}\0${type}\0${stage ?? ''}\0${discriminator}`).slice(0, 48)}`;
}

function isTerminal(status: RunStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled';
}

function uniqueArtifacts(artifacts: readonly ArtifactRef[]): ArtifactRef[] {
  const unique = new Map<string, ArtifactRef>();
  for (const artifact of artifacts) {
    unique.set(artifact.artifact_id, artifact);
  }
  return [...unique.values()];
}

export class StaleDispatchError extends Error {
  readonly code = 'stale_dispatch';
  readonly expectedGeneration: number;
  readonly currentGeneration: number;

  constructor(expectedGeneration: number, currentGeneration: number) {
    super(
      `dispatch generation ${expectedGeneration} is stale; current run generation is ${currentGeneration}`,
    );
    this.name = 'StaleDispatchError';
    this.expectedGeneration = expectedGeneration;
    this.currentGeneration = currentGeneration;
  }
}

class LeaseSession {
  readonly #store: ControlPlaneStore;
  readonly #scope: ControlPlaneScope;
  readonly #clock: Clock;
  readonly #durationMs: number;
  readonly #heartbeatMs: number;
  #lease: Lease;
  #timer: NodeJS.Timeout | null = null;
  #renewing: Promise<void> | null = null;
  #lost: unknown = null;

  private constructor(
    store: ControlPlaneStore,
    scope: ControlPlaneScope,
    lease: Lease,
    clock: Clock,
    durationMs: number,
    heartbeatMs: number,
  ) {
    this.#store = store;
    this.#scope = scope;
    this.#lease = lease;
    this.#clock = clock;
    this.#durationMs = durationMs;
    this.#heartbeatMs = heartbeatMs;
  }

  static async acquire(options: {
    store: ControlPlaneStore;
    scope: ControlPlaneScope;
    runId: RunId;
    workerId: string;
    clock: Clock;
    durationMs: number;
    heartbeatMs: number;
  }): Promise<LeaseSession> {
    const now = options.clock.now();
    const lease = await options.store.acquireLease({
      ...options.scope,
      resource_id: runLeaseResourceId(options.runId),
      lease_owner_id: options.workerId,
      acquired_at: now.toISOString(),
      expires_at: plusMilliseconds(now, options.durationMs),
    });
    const session = new LeaseSession(
      options.store,
      options.scope,
      lease,
      options.clock,
      options.durationMs,
      options.heartbeatMs,
    );
    session.#startHeartbeat();
    return session;
  }

  #startHeartbeat(): void {
    this.#timer = setInterval(() => {
      void this.#renew().catch((error: unknown) => {
        this.#lost = error;
      });
    }, this.#heartbeatMs);
    this.#timer.unref();
  }

  async #renew(): Promise<void> {
    if (this.#renewing !== null) {
      return this.#renewing;
    }
    this.#renewing = (async () => {
      if (this.#lost !== null) {
        throw this.#lost;
      }
      const observed = this.#clock.now();
      if (observed.toISOString() >= this.#lease.expires_at) {
        throw leaseLost(`lease for ${this.#lease.resource_id} expired`);
      }
      this.#lease = await this.#store.renewLease({
        ...this.#scope,
        resource_id: this.#lease.resource_id,
        lease_owner_id: this.#lease.lease_owner_id,
        fencing_token: this.#lease.fencing_token,
        observed_at: observed.toISOString(),
        expires_at: plusMilliseconds(observed, this.#durationMs),
      });
    })().finally(() => {
      this.#renewing = null;
    });
    return this.#renewing;
  }

  async guard(): Promise<LeaseGuard> {
    if (this.#lost !== null) {
      throw this.#lost;
    }
    const observed = this.#clock.now();
    const remaining = Date.parse(this.#lease.expires_at) - observed.getTime();
    if (remaining <= 0) {
      throw leaseLost(`lease for ${this.#lease.resource_id} expired`);
    }
    if (remaining <= this.#heartbeatMs * 2) {
      await this.#renew();
    }
    return {
      ...this.#scope,
      resource_id: this.#lease.resource_id,
      lease_owner_id: this.#lease.lease_owner_id,
      fencing_token: this.#lease.fencing_token,
      observed_at: this.#clock.now().toISOString(),
    };
  }

  async assertActive(): Promise<void> {
    const guard = await this.guard();
    const current = await this.#store.getLease(this.#scope, guard.resource_id);
    if (
      current === null ||
      current.lease_owner_id !== guard.lease_owner_id ||
      current.fencing_token !== guard.fencing_token ||
      current.expires_at <= guard.observed_at
    ) {
      throw leaseLost(`lease for ${guard.resource_id} is no longer active`);
    }
  }

  get fencingToken(): number {
    return this.#lease.fencing_token;
  }

  async close(): Promise<void> {
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    if (this.#renewing !== null) {
      await this.#renewing.catch(() => {});
    }
    if (this.#lost !== null) {
      return;
    }
    const releasedAt = this.#clock.now().toISOString();
    if (releasedAt >= this.#lease.expires_at) {
      return;
    }
    await this.#store
      .releaseLease({
        ...this.#scope,
        resource_id: this.#lease.resource_id,
        lease_owner_id: this.#lease.lease_owner_id,
        fencing_token: this.#lease.fencing_token,
        released_at: releasedAt,
      })
      .catch(() => {});
  }
}

export class DurableBoundaryExecutor {
  readonly #store: ControlPlaneStore;
  readonly #artifactStore: DurableBoundaryExecutorOptions['artifactStore'];
  readonly #stageExecutor: DurableBoundaryExecutorOptions['stageExecutor'];
  readonly #telemetry: HostedTelemetry;
  readonly #plan: readonly StageDefinition[];
  readonly #clock: Clock;
  readonly #leaseDurationMs: number;
  readonly #leaseHeartbeatMs: number;
  readonly #workerId: string;

  constructor(options: DurableBoundaryExecutorOptions) {
    this.#store = options.store;
    this.#artifactStore = options.artifactStore;
    this.#stageExecutor = options.stageExecutor;
    this.#telemetry = options.telemetry ?? noopHostedTelemetry;
    this.#plan = options.stagePlan ?? THREATFOREST_STAGE_PLAN;
    this.#clock = options.clock ?? systemClock;
    this.#leaseDurationMs = options.leaseDurationMs ?? 120_000;
    this.#leaseHeartbeatMs = options.leaseHeartbeatMs ?? 30_000;
    this.#workerId = options.workerId ?? `runtime-${randomUUID()}`;
    validateStagePlan(this.#plan);
    if (this.#leaseDurationMs <= this.#leaseHeartbeatMs * 2) {
      throw new Error('leaseDurationMs must be more than twice leaseHeartbeatMs');
    }
  }

  async startRun(
    scope: ControlPlaneScope,
    input: StartRunInput,
    actorId: string,
    signal: AbortSignal = new AbortController().signal,
  ): Promise<BoundaryResult> {
    if (scope.application_id !== input.applicationId) {
      throw conflict('application scope does not match the start request');
    }
    const application = await this.#store.getApplication(scope);
    if (application === null) {
      throw new ControlPlaneError('not_found', 'application was not found');
    }

    const requestHash = sha256(
      canonicalJson({
        application_id: input.applicationId,
        source_artifact_ids: input.sourceArtifactIds,
        threat_artifact_id: input.threatArtifactId,
        project_path: input.projectPath,
        threat_file_path: input.threatFilePath,
        settings: input.settings,
      }),
    );
    const key = `start_run:${input.idempotencyKey}`;
    const now = this.#clock.now();
    const claim = await this.#store.claimIdempotency(
      IdempotencyRecordSchema.parse({
        schema_version: 1,
        ...scope,
        key,
        operation: 'start_run',
        request_hash: requestHash,
        status: 'in_progress',
        response_artifact: null,
        created_at: now.toISOString(),
        expires_at: plusMilliseconds(now, IDEMPOTENCY_TTL_MS),
      }),
      now.toISOString(),
    );
    if (!claim.acquired && claim.record.status === 'failed') {
      throw conflict(`idempotent start ${input.idempotencyKey} previously failed`);
    }

    const runId = RunIdSchema.parse(
      `run_${sha256(`${scope.owner_id}\0${scope.application_id}\0${key}\0${requestHash}`).slice(0, 48)}`,
    );
    const traceId = sha256(`trace\0${runId}`).slice(0, 32);
    const configHash = sha256(canonicalJson(input.settings));
    let run = await this.#store.getRun(scope, runId);
    let runCreated = false;
    if (run === null) {
      const candidate: RunRecord = {
        schema_version: 1,
        ...scope,
        run_id: runId,
        status: 'queued',
        source_artifact_ids: input.sourceArtifactIds,
        threat_artifact_id: input.threatArtifactId,
        current_stage_id: null,
        trace_id: traceId,
        revision: 1,
        last_event_sequence: -1,
        created_at: claim.record.created_at,
        updated_at: claim.record.created_at,
        completed_at: null,
        error_code: null,
        error_message: null,
      };
      try {
        run = await this.#store.createRun(candidate);
        runCreated = true;
      } catch (error) {
        if (!(error instanceof ControlPlaneError) || error.code !== 'already_exists') {
          throw error;
        }
        run = await this.#store.getRun(scope, runId);
        if (run === null) {
          throw error;
        }
      }
    }

    const settings = RunSettingsSnapshotSchema.parse({
      schema_version: 1,
      ...scope,
      run_id: runId,
      ...input.settings,
      config_hash: configHash,
      created_at: run.created_at,
    });
    await this.#store.putRunSettingsSnapshot(settings);
    if (runCreated) {
      this.#recordTelemetry('threatforest.run.started', scope, run, settings, 'queued');
    }
    if (claim.record.status === 'in_progress') {
      await this.#store.completeIdempotency({
        ...scope,
        key,
        request_hash: requestHash,
        claim_created_at: claim.record.created_at,
        response_artifact: null,
      });
    }
    return this.runUntilBoundary(scope, runId, actorId, signal);
  }

  async runUntilBoundary(
    scope: ControlPlaneScope,
    runId: RunId,
    actorId: string,
    signal: AbortSignal = new AbortController().signal,
    dispatchGeneration?: number,
  ): Promise<BoundaryResult> {
    const initial = await this.#requireRun(scope, runId);
    this.#assertDispatchGeneration(initial, dispatchGeneration);
    if (isTerminal(initial.status)) {
      return { boundary: initial.status === 'completed' ? 'completed' : 'failed', run: initial, actor_id: actorId, interaction: null };
    }

    let lease: LeaseSession;
    try {
      lease = await LeaseSession.acquire({
        store: this.#store,
        scope,
        runId,
        workerId: this.#workerId,
        clock: this.#clock,
        durationMs: this.#leaseDurationMs,
        heartbeatMs: this.#leaseHeartbeatMs,
      });
    } catch (error) {
      if (error instanceof ControlPlaneError && error.code === 'conflict') {
        return {
          boundary: 'busy',
          run: await this.#requireRun(scope, runId),
          actor_id: actorId,
          interaction: null,
        };
      }
      throw error;
    }

    try {
      this.#assertDispatchGeneration(
        await this.#requireRun(scope, runId),
        dispatchGeneration,
      );
      return await this.#runWithLease(scope, runId, actorId, signal, lease);
    } finally {
      await lease.close();
    }
  }

  async requestControl(
    scope: ControlPlaneScope,
    runId: RunId,
    actorId: string,
    action: 'pause' | 'stop',
  ): Promise<BoundaryResult> {
    const initial = await this.#requireRun(scope, runId);
    if (isTerminal(initial.status)) {
      return {
        boundary: initial.status === 'completed' ? 'completed' : 'failed',
        run: initial,
        actor_id: actorId,
        interaction: null,
      };
    }
    if (action === 'pause' && initial.status === 'awaiting_input') {
      return {
        boundary: 'awaiting_input',
        run: initial,
        actor_id: actorId,
        interaction: null,
      };
    }
    await this.#store.requestRunControl({
      ...scope,
      run_id: runId,
      action,
      requested_at: this.#clock.now().toISOString(),
    });
    let lease: LeaseSession;
    try {
      lease = await LeaseSession.acquire({
        store: this.#store,
        scope,
        runId,
        workerId: `${this.#workerId}-control`,
        clock: this.#clock,
        durationMs: this.#leaseDurationMs,
        heartbeatMs: this.#leaseHeartbeatMs,
      });
    } catch (error) {
      if (error instanceof ControlPlaneError && error.code === 'conflict') {
        return {
          boundary: 'busy',
          run: await this.#requireRun(scope, runId),
          actor_id: actorId,
          interaction: null,
        };
      }
      throw error;
    }
    try {
      return (
        (await this.#applyRunControl(scope, runId, actorId, lease)) ?? {
          boundary: 'busy',
          run: await this.#requireRun(scope, runId),
          actor_id: actorId,
          interaction: null,
        }
      );
    } finally {
      await lease.close();
    }
  }

  async #runWithLease(
    scope: ControlPlaneScope,
    runId: RunId,
    actorId: string,
    signal: AbortSignal,
    lease: LeaseSession,
  ): Promise<BoundaryResult> {
    const initialControl = await this.#applyRunControl(
      scope,
      runId,
      actorId,
      lease,
    );
    if (initialControl !== null) {
      return initialControl;
    }
    const settings = await this.#store.getRunSettingsSnapshot(scope, runId);
    if (settings === null) {
      throw new ControlPlaneError('not_found', 'run settings snapshot was not found');
    }
    const executionStart = await this.#requireRun(scope, runId);
    if (executionStart.status === 'queued') {
      const events = await this.#store.listEvents(scope, runId);
      const lastBoundary = [...events]
        .reverse()
        .find((event) =>
          ['run_paused', 'run_stopped', 'stage_failed'].includes(event.type),
        );
      if (lastBoundary !== undefined) {
        await this.#appendEventOnce(scope, runId, lease, {
          type: 'run_resumed',
          stage: executionStart.current_stage_id,
          discriminator: String(executionStart.revision),
          percentage: null,
          message: 'Run resumed',
          payload: {
            generation: executionStart.revision,
            previous_boundary: lastBoundary.type,
          },
        });
      }
    }
    let checkpoints = await this.#store.listCheckpoints(scope, runId);
    const completedIds: string[] = [];

    for (let index = 0; index < this.#plan.length; index += 1) {
      const stage = this.#plan[index]!;
      const matching = checkpoints.filter(
        (item) => item.stage_id === stage.id && item.stage_version === stage.version,
      );
      const completed = matching.find((item) => item.status === 'completed');
      if (completed !== undefined) {
        completedIds.push(stage.id);
        continue;
      }

      const latest = matching.sort((left, right) => right.attempt - left.attempt)[0] ?? null;
      const currentInteraction =
        stage.hitlKind === null
          ? null
          : await this.#store.getHitlRequest(
              scope,
              hitlInteractionId(runId, stage.id),
            );
      if (currentInteraction?.status === 'pending') {
        await this.#repairAwaitingBoundary(
          scope,
          runId,
          settings,
          stage,
          latest,
          currentInteraction,
          index,
          lease,
        );
        const control = await this.#applyRunControl(
          scope,
          runId,
          actorId,
          lease,
        );
        if (control !== null) {
          return control;
        }
        return {
          boundary: 'awaiting_input',
          run: await this.#requireRun(scope, runId),
          actor_id: actorId,
          interaction: currentInteraction,
        };
      }

      const response =
        currentInteraction === null
          ? null
          : await this.#store.getHitlResponse(
              scope,
              currentInteraction.interaction_id,
              currentInteraction.revision,
            );
      const hitlHistory =
        currentInteraction === null
          ? []
          : await this.#hitlHistory(scope, currentInteraction);
      const attempt =
        latest === null
          ? 1
          : latest.status === 'failed' || latest.status === 'cancelled'
            ? latest.attempt + 1
            : latest.attempt;
      const startedAt = latest?.attempt === attempt ? latest.started_at : this.#clock.now().toISOString();
      const started = StageCheckpointSchema.parse({
        schema_version: 1,
        ...scope,
        run_id: runId,
        stage_id: stage.id,
        stage_version: stage.version,
        attempt,
        fencing_token: lease.fencingToken,
        idempotency_key: stageIdempotencyKey(runId, stage),
        trace_id: (await this.#requireRun(scope, runId)).trace_id,
        status: 'started',
        input_artifacts: this.#inputArtifacts(checkpoints, index),
        output_artifacts: latest?.attempt === attempt ? latest.output_artifacts : [],
        model_id: stage.usesModel ? settings.model_id : null,
        config_hash: settings.config_hash,
        started_at: startedAt,
        completed_at: null,
        error_code: null,
        error_message: null,
      });

      const activeRun = await this.#setRunState(scope, runId, lease, {
        status: 'running',
        current_stage_id: stage.id,
        completed_at: null,
        error_code: null,
        error_message: null,
      });
      await this.#store.putCheckpoint(started, await lease.guard());
      const stageStarted = await this.#appendEventOnce(scope, runId, lease, {
        type: 'stage_started',
        stage: stage.id,
        discriminator: String(attempt),
        percentage: (index / this.#plan.length) * 100,
        message: `Started ${stage.id}`,
        payload: { attempt, stage_version: stage.version },
      });
      if (stageStarted) {
        this.#recordTelemetry(
          'threatforest.stage.started',
          scope,
          activeRun,
          settings,
          'running',
          {
            'threatforest.stage.id': stage.id,
            'threatforest.stage.version': stage.version,
            'threatforest.stage.attempt': attempt,
            'threatforest.stage.uses_model': stage.usesModel,
          },
        );
      }
      if (response !== null) {
        const responseRecorded = await this.#appendEventOnce(scope, runId, lease, {
          type: 'hitl_response_received',
          stage: stage.id,
          discriminator: String(response.revision),
          percentage: (index / this.#plan.length) * 100,
          message: response.action === 'skip' ? 'Human review skipped' : 'Human response received',
          payload: { action: response.action, revision: response.revision },
        });
        if (responseRecorded) {
          this.#recordTelemetry(
            'threatforest.hitl.response_received',
            scope,
            activeRun,
            settings,
            response.action === 'skip' ? 'skipped' : 'submitted',
            {
              'threatforest.stage.id': stage.id,
              'threatforest.hitl.kind': stage.hitlKind ?? 'unknown',
              'threatforest.hitl.revision': response.revision,
              'threatforest.hitl.action': response.action,
            },
          );
        }
      }

      let durableStageBoundary = false;
      const stageCancellation = new AbortController();
      const stageSignal = AbortSignal.any([signal, stageCancellation.signal, AbortSignal.timeout(2 * 60 * 60_000)]);
      let checkingControl = false;
      const controlTimer = setInterval(() => {
        if (checkingControl || stageSignal.aborted) return;
        checkingControl = true;
        void (async () => {
          await lease.assertActive();
          const control = await this.#store.getRunControl(scope, runId);
          if (control !== null) stageCancellation.abort(new DOMException('Run control requested', 'AbortError'));
        })().catch(error => stageCancellation.abort(error))
          .finally(() => { checkingControl = false; });
      }, 5_000);
      controlTimer.unref();
      try {
        await lease.assertActive();
        const run = await this.#requireRun(scope, runId);
        const context = {
          scope,
          run,
          settings,
          stage,
          checkpoint: started,
          actorId,
          completedStageIds: Object.freeze([...completedIds]),
          hitlHistory: Object.freeze(hitlHistory),
          response,
          signal: stageSignal,
          assertLease: async (): Promise<void> => lease.assertActive(),
        };
        let result: StageExecutionResult | null = null;
        if (latest?.status === 'started' && this.#stageExecutor.recover !== undefined) {
          result = await this.#stageExecutor.recover(context, latest);
        }
        result ??= await this.#stageExecutor.execute(context);
        await lease.assertActive();
        if (
          result.outputArtifacts?.some(
            (artifact) => artifact.kind === 'checkpoint',
          ) === true
        ) {
          // A workspace receipt is already durable outside DynamoDB. Preserve
          // the started attempt if a following control-plane write fails so a
          // replacement can recover that exact receipt without re-running it.
          durableStageBoundary = true;
        }

        if (result.status === 'awaiting_input') {
          if (stage.hitlKind === null) {
            throw new Error(`non-HITL stage ${stage.id} requested human input`);
          }
          const request = await this.#persistHitlBoundary(
            scope,
            runId,
            stage,
            started,
            currentInteraction,
            result,
            settings,
            index,
            lease,
          );
          durableStageBoundary = true;
          const control = await this.#applyRunControl(
            scope,
            runId,
            actorId,
            lease,
          );
          if (control !== null) {
            return control;
          }
          return {
            boundary: 'awaiting_input',
            run: await this.#requireRun(scope, runId),
            actor_id: actorId,
            interaction: request,
          };
        }

        const completedCheckpoint = StageCheckpointSchema.parse({
          ...started,
          status: 'completed',
          output_artifacts: uniqueArtifacts([
            ...started.output_artifacts,
            ...(result.outputArtifacts ?? []),
          ]),
          completed_at: this.#clock.now().toISOString(),
        });
        await this.#store.putCheckpoint(completedCheckpoint, await lease.guard());
        const stageCompleted = await this.#appendEventOnce(scope, runId, lease, {
          type: 'stage_completed',
          stage: stage.id,
          discriminator: String(attempt),
          percentage: ((index + 1) / this.#plan.length) * 100,
          message: `Completed ${stage.id}`,
          payload: { attempt, stage_version: stage.version },
        });
        if (stageCompleted) {
          this.#recordTelemetry(
            'threatforest.stage.completed',
            scope,
            activeRun,
            settings,
            'completed',
            {
              'threatforest.stage.id': stage.id,
              'threatforest.stage.version': stage.version,
              'threatforest.stage.attempt': attempt,
              'threatforest.stage.uses_model': stage.usesModel,
            },
          );
        }
        durableStageBoundary = true;
        completedIds.push(stage.id);
        checkpoints = await this.#store.listCheckpoints(scope, runId);
        const control = await this.#applyRunControl(
          scope,
          runId,
          actorId,
          lease,
        );
        if (control !== null) {
          return control;
        }
      } catch (error) {
        if (stageCancellation.signal.aborted) {
          await lease.assertActive();
          const control = await this.#applyRunControl(scope, runId, actorId, lease);
          if (control !== null) return control;
        }
        if (error instanceof ControlPlaneError && error.code === 'lease_lost') {
          throw error;
        }
        if (durableStageBoundary) {
          throw error;
        }
        const cancellation =
          error === signal.reason ||
          (error instanceof Error &&
            (error.name === 'AbortError' || error.name === 'GraphCancelledError'));
        if (signal.aborted && cancellation) {
          throw error;
        }
        await this.#recordFailure(
          scope,
          runId,
          settings,
          stage,
          started,
          error,
          lease,
        );
        return {
          boundary: 'failed',
          run: await this.#requireRun(scope, runId),
          actor_id: actorId,
          interaction: null,
        };
      } finally {
        clearInterval(controlTimer);
      }
    }

    await this.#appendEventOnce(scope, runId, lease, {
      type: 'run_completed',
      stage: null,
      discriminator: 'completed',
      percentage: 100,
      message: 'Threat model completed',
      payload: {},
    });
    const run = await this.#setRunState(scope, runId, lease, {
      status: 'completed',
      current_stage_id: null,
      completed_at: this.#clock.now().toISOString(),
      error_code: null,
      error_message: null,
    });
    this.#recordTelemetry(
      'threatforest.run.completed',
      scope,
      run,
      settings,
      'completed',
      {
        'threatforest.run.completed': true,
      },
    );
    return { boundary: 'completed', run, actor_id: actorId, interaction: null };
  }

  async #applyRunControl(
    scope: ControlPlaneScope,
    runId: RunId,
    actorId: string,
    lease: LeaseSession,
  ): Promise<BoundaryResult | null> {
    const intent = await this.#store.getRunControl(scope, runId);
    if (intent === null) {
      return null;
    }
    const current = await this.#requireRun(scope, runId);
    if (isTerminal(current.status)) {
      return {
        boundary: current.status === 'completed' ? 'completed' : 'failed',
        run: current,
        actor_id: actorId,
        interaction: null,
      };
    }
    const updated = await this.#setRunState(scope, runId, lease, {
      status: intent.action === 'stop' ? 'cancelled' : 'awaiting_input',
      current_stage_id: current.current_stage_id,
      completed_at:
        intent.action === 'stop' ? this.#clock.now().toISOString() : null,
      error_code: null,
      error_message: null,
    });
    const controlRecorded = await this.#appendEventOnce(scope, runId, lease, {
      type: intent.action === 'stop' ? 'run_stopped' : 'run_paused',
      stage: updated.current_stage_id,
      discriminator: intent.requested_at,
      percentage: null,
      message: intent.action === 'stop' ? 'Run stopped' : 'Run paused',
      payload: {
        action: intent.action,
        requested_at: intent.requested_at,
      },
    });
    if (controlRecorded) {
      const settings = await this.#store.getRunSettingsSnapshot(scope, runId);
      if (settings !== null) {
        this.#recordTelemetry(
          intent.action === 'stop'
            ? 'threatforest.run.stopped'
            : 'threatforest.run.paused',
          scope,
          updated,
          settings,
          intent.action === 'stop' ? 'cancelled' : 'awaiting_input',
          {
            'threatforest.run.control_action': intent.action,
          },
          intent.action === 'stop' ? 'error' : 'ok',
        );
      }
    }
    return {
      boundary: intent.action === 'stop' ? 'failed' : 'awaiting_input',
      run: await this.#requireRun(scope, runId),
      actor_id: actorId,
      interaction: null,
    };
  }

  async #persistHitlBoundary(
    scope: ControlPlaneScope,
    runId: RunId,
    stage: StageDefinition,
    checkpoint: StageCheckpoint,
    previous: HitlRequest | null,
    result: Extract<StageExecutionResult, { status: 'awaiting_input' }>,
    settings: RunSettingsSnapshot,
    index: number,
    lease: LeaseSession,
  ): Promise<HitlRequest> {
    const revision = (previous?.revision ?? 0) + 1;
    const id = hitlInteractionId(runId, stage.id);
    const transcript = await this.#artifactStore.putTranscript({
      ...scope,
      run_id: runId,
      interaction_id: id,
      revision,
      stage_id: stage.id,
      trace_id: checkpoint.trace_id,
      idempotency_key: `${checkpoint.idempotency_key}:hitl:${revision}`,
      transcript: result.transcript,
    });
    await lease.assertActive();
    const request = HitlRequestSchema.parse({
      schema_version: 1,
      ...scope,
      interaction_id: id,
      run_id: runId,
      stage_id: stage.id,
      kind: stage.hitlKind,
      revision,
      fencing_token: lease.fencingToken,
      trace_id: checkpoint.trace_id,
      status: 'pending',
      reason: result.reason,
      transcript_artifact: transcript,
      created_at: this.#clock.now().toISOString(),
      expires_at: null,
    });
    await this.#store.putCheckpoint(
      StageCheckpointSchema.parse({
        ...checkpoint,
        status: 'awaiting_input',
        output_artifacts: uniqueArtifacts([
          ...checkpoint.output_artifacts,
          ...(result.outputArtifacts ?? []),
          transcript,
        ]),
      }),
      await lease.guard(),
    );
    await this.#store.createHitlRequest(request, await lease.guard());
    const hitlRequested = await this.#appendEventOnce(scope, runId, lease, {
      type: 'hitl_requested',
      stage: stage.id,
      discriminator: String(revision),
      percentage: (index / this.#plan.length) * 100,
      message: `Awaiting input for ${stage.id}`,
      payload: { interaction_id: id, revision, kind: stage.hitlKind },
    });
    const run = await this.#setRunState(scope, runId, lease, {
      status: 'awaiting_input',
      current_stage_id: stage.id,
      completed_at: null,
      error_code: null,
      error_message: null,
    });
    if (hitlRequested) {
      this.#recordTelemetry(
        'threatforest.hitl.requested',
        scope,
        run,
        settings,
        'awaiting_input',
        {
          'threatforest.stage.id': stage.id,
          'threatforest.hitl.kind': stage.hitlKind ?? 'unknown',
          'threatforest.hitl.revision': revision,
        },
      );
    }
    return request;
  }

  async #repairAwaitingBoundary(
    scope: ControlPlaneScope,
    runId: RunId,
    settings: RunSettingsSnapshot,
    stage: StageDefinition,
    latest: StageCheckpoint | null,
    request: HitlRequest,
    index: number,
    lease: LeaseSession,
  ): Promise<void> {
    if (latest?.status !== 'awaiting_input') {
      const artifact = request.transcript_artifact;
      await this.#store.putCheckpoint(
        StageCheckpointSchema.parse({
          schema_version: 1,
          ...scope,
          run_id: runId,
          stage_id: stage.id,
          stage_version: stage.version,
          attempt: latest?.attempt ?? 1,
          fencing_token: lease.fencingToken,
          idempotency_key: stageIdempotencyKey(runId, stage),
          trace_id: request.trace_id,
          status: 'awaiting_input',
          input_artifacts: latest?.input_artifacts ?? [],
          output_artifacts: artifact === null ? [] : [artifact],
          model_id: stage.usesModel ? settings.model_id : null,
          config_hash: settings.config_hash,
          started_at: latest?.started_at ?? request.created_at,
          completed_at: null,
          error_code: null,
          error_message: null,
        }),
        await lease.guard(),
      );
    }
    const hitlRequested = await this.#appendEventOnce(scope, runId, lease, {
      type: 'hitl_requested',
      stage: stage.id,
      discriminator: String(request.revision),
      percentage: (index / this.#plan.length) * 100,
      message: `Awaiting input for ${stage.id}`,
      payload: {
        interaction_id: request.interaction_id,
        revision: request.revision,
        kind: request.kind,
      },
    });
    const run = await this.#setRunState(scope, runId, lease, {
      status: 'awaiting_input',
      current_stage_id: stage.id,
      completed_at: null,
      error_code: null,
      error_message: null,
    });
    if (hitlRequested) {
      this.#recordTelemetry(
        'threatforest.hitl.requested',
        scope,
        run,
        settings,
        'awaiting_input',
        {
          'threatforest.stage.id': stage.id,
          'threatforest.hitl.kind': request.kind,
          'threatforest.hitl.revision': request.revision,
        },
      );
    }
  }

  #inputArtifacts(checkpoints: readonly StageCheckpoint[], stageIndex: number): ArtifactRef[] {
    if (stageIndex === 0) {
      return [];
    }
    const previousId = this.#plan[stageIndex - 1]!.id;
    const previous = checkpoints
      .filter((item) => item.stage_id === previousId && item.status === 'completed')
      .sort((left, right) => right.attempt - left.attempt)[0];
    return previous?.output_artifacts ?? [];
  }

  async #hitlHistory(
    scope: ControlPlaneScope,
    head: HitlRequest,
  ): Promise<Array<{ request: HitlRequest; response: HitlResponse }>> {
    const history: Array<{ request: HitlRequest; response: HitlResponse }> = [];
    for (let revision = 1; revision <= head.revision; revision += 1) {
      const [request, response] = await Promise.all([
        this.#store.getHitlRequest(scope, head.interaction_id, revision),
        this.#store.getHitlResponse(scope, head.interaction_id, revision),
      ]);
      if (request !== null && response !== null) {
        history.push({ request, response });
      }
    }
    return history;
  }

  async #recordFailure(
    scope: ControlPlaneScope,
    runId: RunId,
    settings: RunSettingsSnapshot,
    stage: StageDefinition,
    checkpoint: StageCheckpoint,
    error: unknown,
    lease: LeaseSession,
  ): Promise<void> {
    const detail = compactError(error);
    await this.#store.putCheckpoint(
      StageCheckpointSchema.parse({
        ...checkpoint,
        status: 'failed',
        completed_at: this.#clock.now().toISOString(),
        error_code: detail.code.slice(0, 128),
        error_message: detail.message,
      }),
      await lease.guard(),
    );
    const failureRecorded = await this.#appendEventOnce(scope, runId, lease, {
      type: 'stage_failed',
      stage: stage.id,
      discriminator: String(checkpoint.attempt),
      percentage: null,
      message: detail.message,
      payload: { error_code: detail.code },
    });
    const run = await this.#setRunState(scope, runId, lease, {
      status: 'failed',
      current_stage_id: stage.id,
      completed_at: this.#clock.now().toISOString(),
      error_code: detail.code.slice(0, 128),
      error_message: detail.message,
    });
    if (failureRecorded) {
      this.#recordTelemetry(
        'threatforest.stage.failed',
        scope,
        run,
        settings,
        'failed',
        {
          'threatforest.stage.id': stage.id,
          'threatforest.stage.version': stage.version,
          'threatforest.stage.attempt': checkpoint.attempt,
          'threatforest.stage.uses_model': stage.usesModel,
          'threatforest.error.code': detail.code.slice(0, 128),
        },
        'error',
      );
    }
  }

  #recordTelemetry(
    spanName: string,
    scope: ControlPlaneScope,
    run: RunRecord,
    settings: RunSettingsSnapshot,
    outcome: string,
    attributes: Readonly<Record<string, HostedTelemetryAttributeValue>> = {},
    status: 'ok' | 'error' = 'ok',
  ): void {
    try {
      this.#telemetry.record({
        spanName,
        status,
        attributes: {
          ...runTelemetryAttributes(scope, run, settings, outcome),
          ...attributes,
        },
      });
    } catch {
      // Observability is best effort and must not alter durable execution.
    }
  }

  async #appendEventOnce(
    scope: ControlPlaneScope,
    runId: RunId,
    lease: LeaseSession,
    input: {
      type: string;
      stage: string | null;
      discriminator: string;
      percentage: number | null;
      message: string | null;
      payload: Record<string, unknown>;
    },
  ): Promise<boolean> {
    const id = eventId(runId, input.type, input.stage, input.discriminator);
    const existing = await this.#store.listEvents(scope, runId);
    if (existing.some((event) => event.event_id === id)) {
      return false;
    }
    const run = await this.#requireRun(scope, runId);
    await this.#store.appendEvent(
      {
        schema_version: 1,
        ...scope,
        run_id: runId,
        sequence: run.last_event_sequence + 1,
        event_id: id,
        trace_id: run.trace_id,
        type: input.type,
        stage: input.stage,
        percentage: input.percentage,
        message: input.message,
        payload: input.payload,
        emitted_at: this.#clock.now().toISOString(),
      },
      await lease.guard(),
    );
    return true;
  }

  async #setRunState(
    scope: ControlPlaneScope,
    runId: RunId,
    lease: LeaseSession,
    patch: Pick<
      RunRecord,
      | 'status'
      | 'current_stage_id'
      | 'completed_at'
      | 'error_code'
      | 'error_message'
    >,
  ): Promise<RunRecord> {
    const current = await this.#requireRun(scope, runId);
    if (
      current.status === patch.status &&
      current.current_stage_id === patch.current_stage_id &&
      current.completed_at === patch.completed_at &&
      current.error_code === patch.error_code &&
      current.error_message === patch.error_message
    ) {
      return current;
    }
    return this.#store.updateRun(
      {
        ...current,
        ...patch,
        revision: current.revision + 1,
        updated_at: this.#clock.now().toISOString(),
      },
      current.revision,
      await lease.guard(),
    );
  }

  async #requireRun(scope: ControlPlaneScope, runId: RunId): Promise<RunRecord> {
    const run = await this.#store.getRun(scope, runId);
    if (run === null) {
      throw new ControlPlaneError('not_found', `run ${runId} was not found`);
    }
    if (!sameScope(run, scope)) {
      throw new ControlPlaneError('not_found', `run ${runId} was not found`);
    }
    return run;
  }

  #assertDispatchGeneration(
    run: RunRecord,
    dispatchGeneration: number | undefined,
  ): void {
    if (
      dispatchGeneration !== undefined &&
      run.revision !== dispatchGeneration
    ) {
      throw new StaleDispatchError(dispatchGeneration, run.revision);
    }
  }
}

export function parseStartRunInput(value: {
  applicationId: string;
  sourceArtifactIds: readonly string[];
  threatArtifactId: string | null;
  projectPath: string | null;
  threatFilePath: string | null;
  settings: StartRunInput['settings'];
  idempotencyKey: string;
}): StartRunInput {
  return {
    applicationId: ApplicationIdSchema.parse(value.applicationId),
    sourceArtifactIds: value.sourceArtifactIds.map((id) => ArtifactIdSchema.parse(id)),
    threatArtifactId:
      value.threatArtifactId === null ? null : ArtifactIdSchema.parse(value.threatArtifactId),
    projectPath: value.projectPath,
    threatFilePath: value.threatFilePath,
    settings: value.settings,
    idempotencyKey: value.idempotencyKey,
  };
}
