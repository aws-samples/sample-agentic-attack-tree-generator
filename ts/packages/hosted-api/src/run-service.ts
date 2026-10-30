import {
  ArtifactIdSchema,
  InteractionIdSchema,
  RunConfigSchema,
  runDisplayName,
  type ApplicationId,
  type ArtifactId,
  type HitlResponse,
  type InteractionId,
  type RunConfig,
  type RunId,
  type RunSettingsSnapshot,
  type RunState,
  type UserId,
} from '@threatforest/types';
import type {
  ControlPlaneScope,
  ControlPlaneStore,
  RunRecord,
  RunStatus,
} from '@threatforest/control-plane';
import {
  HostedApiError,
  conflict,
  notFound,
  unprocessable,
} from './errors.js';
import type {
  ArtifactResolver,
  Clock,
  HostedRunView,
  IdFactory,
  MutationContext,
  MutationResponseRecord,
  RunIndex,
  RunOrchestrator,
} from './contracts.js';
import { ApplicationService } from './application-service.js';
import { SettingsService } from './settings-service.js';
import { IdempotencyExecutor, requestHash } from './idempotency.js';
import { asApplicationId, asRunId } from './runtime.js';

interface HostedCreateRunBody extends Record<string, unknown> {
  source_artifact_ids?: unknown;
  threat_artifact_id?: unknown;
}

export interface RunServiceOptions {
  controlPlane: ControlPlaneStore;
  applications: ApplicationService;
  settings: SettingsService;
  runIndex: RunIndex;
  orchestrator: RunOrchestrator;
  artifacts: ArtifactResolver;
  idempotency: IdempotencyExecutor;
  ids: IdFactory;
  clock: Clock;
}

function legacyStatus(status: RunStatus): string {
  const mapped: Record<RunStatus, string> = {
    queued: 'pending',
    running: 'running',
    awaiting_input: 'paused',
    completed: 'complete',
    failed: 'failed',
    cancelled: 'stopped',
  };
  return mapped[status];
}

function selectedFrameworks(config: RunConfig, fallback: string[]): string[] {
  const frameworks = config.frameworks ?? fallback;
  const unique = [...new Set(frameworks.map((value) => value.trim()).filter(Boolean))];
  if (unique.length === 0) {
    throw unprocessable('Select at least one framework.');
  }
  if (unique.some((value) => value.length > 128)) {
    throw unprocessable('Framework identifiers must not exceed 128 characters.');
  }
  return unique;
}

export class RunService {
  readonly #controlPlane: ControlPlaneStore;
  readonly #applications: ApplicationService;
  readonly #settings: SettingsService;
  readonly #runIndex: RunIndex;
  readonly #orchestrator: RunOrchestrator;
  readonly #artifacts: ArtifactResolver;
  readonly #idempotency: IdempotencyExecutor;
  readonly #ids: IdFactory;
  readonly #clock: Clock;

  constructor(options: RunServiceOptions) {
    this.#controlPlane = options.controlPlane;
    this.#applications = options.applications;
    this.#settings = options.settings;
    this.#runIndex = options.runIndex;
    this.#orchestrator = options.orchestrator;
    this.#artifacts = options.artifacts;
    this.#idempotency = options.idempotency;
    this.#ids = options.ids;
    this.#clock = options.clock;
  }

  async create(
    context: MutationContext,
    input: unknown,
  ): Promise<MutationResponseRecord & { value: { run_id: string } }> {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw unprocessable('Run configuration must be a JSON object.');
    }
    const raw = input as HostedCreateRunBody;
    const config = RunConfigSchema.parse({
      ...raw,
      project_path: raw.project_path ?? '',
    });
    if (config.app_id === null) {
      throw unprocessable('app_id is required to start a hosted run.');
    }
    const applicationId = asApplicationId(config.app_id);
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'create_run',
      raw,
      async () => {
        const { record: application, metadata } = await this.#applications.requireWritable(
          context.ownerId,
          applicationId,
        );
        const sourceArtifactIds = await this.#sourceArtifacts(scope, raw.source_artifact_ids);
        const threatArtifactId =
          raw.threat_artifact_id === undefined || raw.threat_artifact_id === null
            ? null
            : ArtifactIdSchema.parse(raw.threat_artifact_id);
        await this.#artifacts.assertReadable(
          scope,
          threatArtifactId === null
            ? sourceArtifactIds
            : [...sourceArtifactIds, threatArtifactId],
        );
        const settings = await this.#settings.settings(context.ownerId, applicationId);
        const frameworks = selectedFrameworks(config, settings.frameworks);
        const runId = this.#ids.runId();
        const now = this.#clock.now().toISOString();
        const snapshotInput = {
          provider: settings.provider,
          model_id: settings.model_id,
          aws_region: settings.aws_region,
          model_parameters: settings.model_parameters,
          frameworks,
          embeddings_model: settings.embeddings_model,
          business_context: structuredClone(metadata.businessContext),
          business_context_updated_at: application.updated_at,
        };
        const snapshot: RunSettingsSnapshot = {
          schema_version: 1,
          ...scope,
          run_id: runId,
          ...snapshotInput,
          config_hash: requestHash('run_settings', snapshotInput),
          created_at: now,
        };
        const run: RunRecord = {
          schema_version: 1,
          ...scope,
          run_id: runId,
          display_name: runDisplayName(application.name, now),
          status: 'queued',
          source_artifact_ids: sourceArtifactIds,
          threat_artifact_id: threatArtifactId,
          current_stage_id: null,
          trace_id: this.#ids.traceId(),
          revision: 1,
          last_event_sequence: -1,
          created_at: now,
          updated_at: now,
          completed_at: null,
          error_code: null,
          error_message: null,
        };
        await this.#controlPlane.createRunDispatch(run, snapshot);
        await this.#runIndex.put({
          ownerId: context.ownerId,
          applicationId,
          runId,
        });
        await this.#orchestrator.dispatch({ run, resumedFromRunId: null });
        return { status: 202, value: { run_id: runId } };
      },
    );
  }

  async sources(ownerId: UserId, applicationId: ApplicationId) {
    await this.#applications.get(ownerId, applicationId);
    const scope = { owner_id: ownerId, application_id: applicationId };
    const [ready, descriptions] = await Promise.all([
      this.#artifacts.listReadySourceArtifacts(scope),
      this.#artifacts.describeSources?.(scope) ?? Promise.resolve([]),
    ]);
    const byId = new Map(descriptions.map(source => [source.artifact_id, source]));
    return { sources: ready.map(id => byId.get(id) ?? { artifact_id: id, filename: 'Uploaded source', created_at: '' }) };
  }

  async list(
    ownerId: UserId,
    statuses?: Set<string>,
  ): Promise<{ runs: RunState[] }> {
    const entries = await this.#runIndex.list(ownerId);
    const views = await Promise.all(
      entries.map(async (entry) => {
        const scope = {
          owner_id: ownerId,
          application_id: entry.applicationId,
        };
        const run = await this.#controlPlane.getRun(scope, entry.runId);
        return run === null ? null : this.#state(run, '');
      }),
    );
    return {
      runs: views
        .filter((run): run is RunState => run !== null)
        .filter((run) => statuses === undefined || statuses.has(run.status))
        .sort((left, right) => right.started_at.localeCompare(left.started_at)),
    };
  }

  async get(ownerId: UserId, runId: RunId): Promise<HostedRunView> {
    const located = await this.locate(ownerId, runId);
    const run = await this.#controlPlane.getRun(
      {
        owner_id: ownerId,
        application_id: located.applicationId,
      },
      runId,
    );
    if (run === null) {
      throw notFound(`Unknown run_id: ${runId}`);
    }
    // Runs retain their own ownership and lifecycle after application deletion.
    // Missing display context must not make an existing run impossible to stop.
    const application = await this.#applications.get(ownerId, located.applicationId)
      .catch((error: unknown) => {
        if (error instanceof HostedApiError && error.status === 404) return null;
        throw error;
      });
    return {
      state: this.#state(run, application?.project_path ?? '', application?.name),
      applicationId: located.applicationId,
    };
  }

  async getRecord(ownerId: UserId, runId: RunId): Promise<RunRecord> {
    const located = await this.locate(ownerId, runId);
    return this.getRecordForScope(
      { owner_id: ownerId, application_id: located.applicationId },
      runId,
    );
  }

  async getRecordForScope(scope: ControlPlaneScope, runId: RunId): Promise<RunRecord> {
    const run = await this.#controlPlane.getRun(scope, runId);
    if (run === null) {
      throw notFound(`Unknown run_id: ${runId}`);
    }
    return run;
  }

  async locate(
    ownerId: UserId,
    runId: RunId,
  ): Promise<{ applicationId: ApplicationId }> {
    const entry = await this.#runIndex.locate(ownerId, runId);
    if (entry === null) {
      throw notFound(`Unknown run_id: ${runId}`);
    }
    return { applicationId: entry.applicationId };
  }

  async control(
    context: MutationContext,
    runId: RunId,
    action: 'pause' | 'stop',
  ): Promise<MutationResponseRecord> {
    const located = await this.locate(context.ownerId, runId);
    const scope = {
      owner_id: context.ownerId,
      application_id: located.applicationId,
    };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      `${action}_run`,
      { runId },
      async () => {
        const run = await this.getRecordForScope(scope, runId);
        const allowed =
          action === 'pause'
            ? ['queued', 'running']
            : ['queued', 'running', 'awaiting_input'];
        if (!allowed.includes(run.status)) {
          throw conflict(`Run ${runId} cannot be ${action}d while ${run.status}.`);
        }
        await this.#controlPlane.requestRunControl({
          ...scope,
          run_id: runId,
          action,
          requested_at: this.#clock.now().toISOString(),
        });
        await this.#orchestrator.requestControl(scope, runId, action);
        return { status: 200, value: { status: `${action}_requested` } };
      },
    );
  }

  async resume(
    context: MutationContext,
    runId: RunId,
  ): Promise<MutationResponseRecord & { value: { new_run_id: string } }> {
    const located = await this.locate(context.ownerId, runId);
    const scope = {
      owner_id: context.ownerId,
      application_id: located.applicationId,
    };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'resume_run',
      { runId },
      async () => {
        await this.#applications.requireWritable(
          context.ownerId,
          located.applicationId,
        );
        const previous = await this.getRecordForScope(scope, runId);
        if (
          previous.status !== 'awaiting_input' &&
          previous.status !== 'cancelled' &&
          previous.status !== 'failed'
        ) {
          throw conflict(`Run ${runId} cannot be resumed while ${previous.status}.`);
        }
        if (
          previous.status === 'awaiting_input' &&
          (
            await this.#controlPlane.listPendingHitl(scope, runId)
          ).length > 0
        ) {
          throw conflict(
            `Run ${runId} is awaiting a human response and cannot be resumed directly.`,
          );
        }
        const previousSettings = await this.#controlPlane.getRunSettingsSnapshot(scope, runId);
        if (previousSettings === null) {
          throw notFound(`Settings snapshot for run ${runId} was not found.`);
        }
        const now = this.#clock.now().toISOString();
        void previousSettings;
        const run = await this.#controlPlane.resumeRun({
          ...scope,
          run_id: runId,
          expected_revision: previous.revision,
          expected_status: previous.status,
          resumed_at: now,
        });
        await this.#orchestrator.dispatch({ run, resumedFromRunId: runId });
        return { status: 202, value: { new_run_id: runId } };
      },
    );
  }

  async #sourceArtifacts(
    scope: ControlPlaneScope,
    rawArtifactIds: unknown,
  ): Promise<ArtifactId[]> {
    let sourceArtifactIds: ArtifactId[];
    if (rawArtifactIds === undefined) {
      sourceArtifactIds = await this.#artifacts.listReadySourceArtifacts(scope);
    } else {
      if (!Array.isArray(rawArtifactIds)) {
        throw unprocessable('source_artifact_ids must be an array.');
      }
      sourceArtifactIds = rawArtifactIds.map((value) => ArtifactIdSchema.parse(value));
    }
    sourceArtifactIds = [...new Set(sourceArtifactIds)];
    if (sourceArtifactIds.length === 0) {
      throw unprocessable(
        'A hosted run requires at least one completed upload source artifact.',
      );
    }
    if (sourceArtifactIds.length > 10_000) {
      throw unprocessable('A run cannot reference more than 10,000 source artifacts.');
    }
    return sourceArtifactIds;
  }

  #state(run: RunRecord, projectPath: string, applicationName?: string): RunState {
    const status = legacyStatus(run.status);
    const config: RunConfig = {
      project_path: projectPath,
      threat_source: run.threat_artifact_id === null ? 'auto' : 'file',
      threat_file_path: null,
      frameworks: null,
      resume_run_dir: null,
      skip_nodes: [],
      app_id: run.application_id,
    };
    return {
      run_id: run.run_id,
      display_name: run.display_name || runDisplayName(applicationName, run.created_at),
      status,
      config,
      started_at: run.created_at,
      completed_at: run.completed_at,
      output_dir: null,
      error: run.error_message,
      paused_at_stage: run.status === 'awaiting_input' ? run.current_stage_id : null,
      paused_at: run.status === 'awaiting_input' ? run.updated_at : null,
    };
  }
}

export interface HitlServiceOptions {
  controlPlane: ControlPlaneStore;
  runs: RunService;
  orchestrator: RunOrchestrator;
  idempotency: IdempotencyExecutor;
  clock: Clock;
}

export class HitlService {
  readonly #controlPlane: ControlPlaneStore;
  readonly #runs: RunService;
  readonly #orchestrator: RunOrchestrator;
  readonly #idempotency: IdempotencyExecutor;
  readonly #clock: Clock;

  constructor(options: HitlServiceOptions) {
    this.#controlPlane = options.controlPlane;
    this.#runs = options.runs;
    this.#orchestrator = options.orchestrator;
    this.#idempotency = options.idempotency;
    this.#clock = options.clock;
  }

  async pending(ownerId: UserId, runId: RunId) {
    const run = await this.#runs.getRecord(ownerId, runId);
    return this.#controlPlane.listPendingHitl(run, runId);
  }

  async respondLegacy(
    context: MutationContext,
    runId: RunId,
    text: string | null,
  ): Promise<MutationResponseRecord> {
    const run = await this.#runs.getRecord(context.ownerId, runId);
    const pending = await this.#controlPlane.listPendingHitl(run, runId);
    if (pending.length === 0) {
      throw notFound(`Run ${runId} has no pending interaction.`);
    }
    if (pending.length > 1) {
      throw conflict(
        'Run has multiple pending interactions; use the versioned interaction endpoint.',
      );
    }
    const request = pending[0]!;
    return this.respond(
      context,
      runId,
      request.interaction_id,
      request.revision,
      text === null ? 'skip' : 'submit',
      text,
    );
  }

  async respond(
    context: MutationContext,
    runId: RunId,
    interactionId: InteractionId,
    revision: number,
    action: HitlResponse['action'],
    text: string | null,
  ): Promise<MutationResponseRecord> {
    InteractionIdSchema.parse(interactionId);
    if (!Number.isSafeInteger(revision) || revision < 1) {
      throw unprocessable('HITL revision must be a positive integer.');
    }
    if (action === 'submit' && (text === null || text.length === 0)) {
      throw unprocessable('A submitted HITL response must include text.');
    }
    if (action === 'skip' && text !== null) {
      throw unprocessable('A skipped HITL response must have null text.');
    }
    if (text !== null && text.length > 1_000_000) {
      throw unprocessable('HITL response exceeds 1,000,000 characters.');
    }
    const run = await this.#runs.getRecord(context.ownerId, runId);
    const scope = {
      owner_id: context.ownerId,
      application_id: run.application_id,
    };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'respond_hitl',
      { runId, interactionId, revision, action, text },
      async () => {
        const request = await this.#controlPlane.getHitlRequest(
          scope,
          interactionId,
          revision,
        );
        if (request === null || request.run_id !== runId) {
          throw notFound('Matching HITL request was not found.');
        }
        const response: HitlResponse = {
          schema_version: 1,
          ...scope,
          interaction_id: interactionId,
          run_id: runId,
          revision,
          action,
          text,
          submitted_at: this.#clock.now().toISOString(),
        };
        await this.#controlPlane.respondToHitl(response);
        await this.#orchestrator.continue(scope, runId, run.trace_id);
        return { status: 200, value: { ok: true } };
      },
    );
  }
}

export function runId(value: unknown): RunId {
  return asRunId(value);
}
