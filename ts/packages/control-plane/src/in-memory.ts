import { isDeepStrictEqual } from 'node:util';
import type {
  HitlRequest,
  HitlResponse,
  HostedProgressEvent,
  IdempotencyRecord,
  InteractionId,
  Lease,
  RunId,
  RunSettingsSnapshot,
  StageCheckpoint,
  UserId,
} from '@threatforest/types';
import {
  alreadyExists,
  conflict,
  immutableRecord,
  invalidInput,
  leaseLost,
  notFound,
  staleRevision,
} from './errors.js';
import { encodeKeyPart, runLeaseResourceId, sequenceKey } from './keys.js';
import type {
  AcquireLeaseInput,
  ApplicationRecord,
  ApplicationSettingsRecord,
  ControlPlaneScope,
  IdempotencyClaim,
  IdempotencyCompletionInput,
  IdempotencyFailureInput,
  LeaseGuard,
  ReleaseLeaseInput,
  RenewLeaseInput,
  RunControlIntent,
  RunRecord,
  ResumeRunInput,
} from './models.js';
import type { ControlPlaneStore } from './store.js';

function copy<T>(value: T): T {
  return structuredClone(value);
}

function scopeKey(scope: ControlPlaneScope): string {
  return `${encodeKeyPart(scope.owner_id)}:${encodeKeyPart(scope.application_id)}`;
}

function scopedKey(scope: ControlPlaneScope, kind: string, id = ''): string {
  return `${scopeKey(scope)}:${kind}:${encodeKeyPart(id)}`;
}

function checkpointKey(checkpoint: StageCheckpoint): string {
  return scopedKey(
    checkpoint,
    'checkpoint',
    `${checkpoint.run_id}:${checkpoint.stage_id}:${checkpoint.stage_version}:${checkpoint.attempt}`,
  );
}

function eventKey(event: HostedProgressEvent): string {
  return scopedKey(event, 'event', `${event.run_id}:${sequenceKey(event.sequence)}`);
}

function hitlKey(scope: ControlPlaneScope, interactionId: InteractionId, revision: number): string {
  return scopedKey(scope, 'hitl', `${interactionId}:${revision}`);
}

function hitlHeadKey(scope: ControlPlaneScope, interactionId: InteractionId): string {
  return scopedKey(scope, 'hitl-head', interactionId);
}

function assertSameScope(left: ControlPlaneScope, right: ControlPlaneScope): void {
  if (left.owner_id !== right.owner_id || left.application_id !== right.application_id) {
    throw invalidInput('owner_id and application_id must match the requested scope');
  }
}

function validateRevision(nextRevision: number, expectedRevision: number): void {
  if (nextRevision !== expectedRevision + 1) {
    throw invalidInput(`revision must advance from ${expectedRevision} to ${expectedRevision + 1}`);
  }
}

function validateHitlResponse(response: HitlResponse): void {
  if (response.action === 'skip' && response.text !== null) {
    throw invalidInput('a skipped HITL response must have null text');
  }
  if (response.action === 'submit' && response.text === null) {
    throw invalidInput('a submitted HITL response must include text');
  }
}

export class InMemoryControlPlane implements ControlPlaneStore {
  readonly #applications = new Map<string, ApplicationRecord>();
  readonly #applicationSettings = new Map<string, ApplicationSettingsRecord>();
  readonly #settingsSnapshots = new Map<string, RunSettingsSnapshot>();
  readonly #runs = new Map<string, RunRecord>();
  readonly #runControls = new Map<string, RunControlIntent>();
  readonly #checkpoints = new Map<string, StageCheckpoint>();
  readonly #events = new Map<string, HostedProgressEvent>();
  readonly #leases = new Map<string, Lease>();
  readonly #idempotency = new Map<string, IdempotencyRecord>();
  readonly #hitlRequests = new Map<string, HitlRequest>();
  readonly #hitlResponses = new Map<string, HitlResponse>();
  readonly #hitlHeads = new Map<string, number>();

  async createApplication(application: ApplicationRecord): Promise<ApplicationRecord> {
    if (application.revision !== 1) {
      throw invalidInput('a new application must start at revision 1');
    }
    const key = scopedKey(application, 'application');
    if (this.#applications.has(key)) {
      throw alreadyExists(`application ${application.application_id} already exists`);
    }
    this.#applications.set(key, copy(application));
    return copy(application);
  }

  async getApplication(scope: ControlPlaneScope): Promise<ApplicationRecord | null> {
    const application = this.#applications.get(scopedKey(scope, 'application'));
    return application === undefined ? null : copy(application);
  }

  async listApplications(ownerId: UserId): Promise<ApplicationRecord[]> {
    return [...this.#applications.values()]
      .filter((application) => application.owner_id === ownerId)
      .sort((left, right) => left.application_id.localeCompare(right.application_id))
      .map(copy);
  }

  async updateApplication(
    application: ApplicationRecord,
    expectedRevision: number,
  ): Promise<ApplicationRecord> {
    validateRevision(application.revision, expectedRevision);
    const key = scopedKey(application, 'application');
    const current = this.#applications.get(key);
    if (current === undefined) {
      throw notFound(`application ${application.application_id} was not found`);
    }
    if (current.revision !== expectedRevision) {
      throw conflict(`application revision is ${current.revision}, not ${expectedRevision}`);
    }
    if (application.created_at !== current.created_at) {
      throw immutableRecord('application created_at cannot be changed');
    }
    this.#applications.set(key, copy(application));
    return copy(application);
  }

  async putApplicationSettings(
    settings: ApplicationSettingsRecord,
    expectedRevision: number | null,
  ): Promise<ApplicationSettingsRecord> {
    const key = scopedKey(settings, 'application-settings');
    const current = this.#applicationSettings.get(key);
    if (expectedRevision === null) {
      if (settings.revision !== 1) {
        throw invalidInput('new application settings must start at revision 1');
      }
      if (current !== undefined) {
        throw alreadyExists('application settings already exist');
      }
    } else {
      validateRevision(settings.revision, expectedRevision);
      if (current === undefined) {
        throw notFound('application settings were not found');
      }
      if (current.revision !== expectedRevision) {
        throw conflict(`settings revision is ${current.revision}, not ${expectedRevision}`);
      }
    }
    this.#applicationSettings.set(key, copy(settings));
    return copy(settings);
  }

  async getApplicationSettings(
    scope: ControlPlaneScope,
  ): Promise<ApplicationSettingsRecord | null> {
    const settings = this.#applicationSettings.get(scopedKey(scope, 'application-settings'));
    return settings === undefined ? null : copy(settings);
  }

  async putRunSettingsSnapshot(snapshot: RunSettingsSnapshot): Promise<RunSettingsSnapshot> {
    const key = scopedKey(snapshot, 'run-settings', snapshot.run_id);
    const current = this.#settingsSnapshots.get(key);
    if (current !== undefined) {
      if (isDeepStrictEqual(current, snapshot)) {
        return copy(current);
      }
      throw immutableRecord(`settings snapshot for run ${snapshot.run_id} is immutable`);
    }
    this.#settingsSnapshots.set(key, copy(snapshot));
    return copy(snapshot);
  }

  async getRunSettingsSnapshot(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<RunSettingsSnapshot | null> {
    const snapshot = this.#settingsSnapshots.get(scopedKey(scope, 'run-settings', runId));
    return snapshot === undefined ? null : copy(snapshot);
  }

  async createRun(run: RunRecord): Promise<RunRecord> {
    if (run.revision !== 1 || run.last_event_sequence !== -1) {
      throw invalidInput('a new run must start at revision 1 with last_event_sequence -1');
    }
    const key = scopedKey(run, 'run', run.run_id);
    if (this.#runs.has(key)) {
      throw alreadyExists(`run ${run.run_id} already exists`);
    }
    this.#runs.set(key, copy(run));
    return copy(run);
  }

  async createRunDispatch(
    run: RunRecord,
    settings: RunSettingsSnapshot,
  ): Promise<RunRecord> {
    const created = await this.createRun(run);
    await this.putRunSettingsSnapshot(settings);
    return created;
  }

  async getRun(scope: ControlPlaneScope, runId: RunId): Promise<RunRecord | null> {
    const run = this.#runs.get(scopedKey(scope, 'run', runId));
    return run === undefined ? null : copy(run);
  }

  async requestRunControl(intent: RunControlIntent): Promise<RunControlIntent> {
    if ((await this.getRun(intent, intent.run_id)) === null) {
      throw notFound(`run ${intent.run_id} was not found`);
    }
    const key = scopedKey(intent, 'run-control', intent.run_id);
    const current = this.#runControls.get(key);
    if (current?.action === 'stop' || current?.action === intent.action) {
      return copy(current);
    }
    this.#runControls.set(key, copy(intent));
    return copy(intent);
  }

  async getRunControl(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<RunControlIntent | null> {
    const intent = this.#runControls.get(scopedKey(scope, 'run-control', runId));
    return intent === undefined ? null : copy(intent);
  }

  async updateRun(run: RunRecord, expectedRevision: number, lease: LeaseGuard): Promise<RunRecord> {
    assertSameScope(run, lease);
    this.#assertRunLease(lease, run.run_id);
    validateRevision(run.revision, expectedRevision);
    const key = scopedKey(run, 'run', run.run_id);
    const current = this.#runs.get(key);
    if (current === undefined) {
      throw notFound(`run ${run.run_id} was not found`);
    }
    if (current.revision !== expectedRevision) {
      throw conflict(`run revision is ${current.revision}, not ${expectedRevision}`);
    }
    if (
      run.created_at !== current.created_at ||
      run.last_event_sequence !== current.last_event_sequence
    ) {
      throw immutableRecord('run created_at and last_event_sequence are store-managed');
    }
    this.#runs.set(key, copy(run));
    return copy(run);
  }

  async resumeRun(input: ResumeRunInput): Promise<RunRecord> {
    const key = scopedKey(input, 'run', input.run_id);
    const current = this.#runs.get(key);
    if (current === undefined) {
      throw notFound(`run ${input.run_id} was not found`);
    }
    if (
      current.revision !== input.expected_revision ||
      current.status !== input.expected_status ||
      !['failed', 'cancelled', 'awaiting_input'].includes(current.status)
    ) {
      throw conflict(
        `run ${input.run_id} cannot resume from revision ${current.revision} while ${current.status}`,
      );
    }
    const controlKey = scopedKey(input, 'run-control', input.run_id);
    if (
      current.status === 'awaiting_input' &&
      this.#runControls.get(controlKey)?.action !== 'pause'
    ) {
      throw conflict(
        `run ${input.run_id} is awaiting human input, not manually paused`,
      );
    }
    const resumed: RunRecord = {
      ...current,
      status: 'queued',
      revision: current.revision + 1,
      updated_at: input.resumed_at,
      completed_at: null,
      error_code: null,
      error_message: null,
    };
    this.#runs.set(key, copy(resumed));
    this.#runControls.delete(controlKey);
    return copy(resumed);
  }

  async putCheckpoint(checkpoint: StageCheckpoint, lease: LeaseGuard): Promise<StageCheckpoint> {
    assertSameScope(checkpoint, lease);
    this.#assertRunLease(lease, checkpoint.run_id);
    if (checkpoint.fencing_token !== lease.fencing_token) {
      throw leaseLost('checkpoint fencing_token does not match the active lease');
    }
    const key = checkpointKey(checkpoint);
    const current = this.#checkpoints.get(key);
    if (current?.status === 'completed') {
      if (isDeepStrictEqual(current, checkpoint)) {
        return copy(current);
      }
      throw immutableRecord('a completed checkpoint cannot be changed');
    }
    if (current !== undefined && current.fencing_token > checkpoint.fencing_token) {
      throw leaseLost('checkpoint was already written by a newer lease holder');
    }
    this.#checkpoints.set(key, copy(checkpoint));
    return copy(checkpoint);
  }

  async listCheckpoints(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<StageCheckpoint[]> {
    return [...this.#checkpoints.values()]
      .filter(
        (checkpoint) =>
          checkpoint.owner_id === scope.owner_id &&
          checkpoint.application_id === scope.application_id &&
          checkpoint.run_id === runId,
      )
      .sort(
        (left, right) =>
          left.started_at.localeCompare(right.started_at) ||
          left.stage_id.localeCompare(right.stage_id) ||
          left.attempt - right.attempt,
      )
      .map(copy);
  }

  async appendEvent(event: HostedProgressEvent, lease: LeaseGuard): Promise<HostedProgressEvent> {
    assertSameScope(event, lease);
    this.#assertRunLease(lease, event.run_id);
    const runKey = scopedKey(event, 'run', event.run_id);
    const run = this.#runs.get(runKey);
    if (run === undefined) {
      throw notFound(`run ${event.run_id} was not found`);
    }
    const expected = run.last_event_sequence + 1;
    if (event.sequence !== expected) {
      throw conflict(`event sequence must be ${expected}, not ${event.sequence}`);
    }
    const key = eventKey(event);
    if (this.#events.has(key)) {
      throw alreadyExists(`event sequence ${event.sequence} already exists`);
    }
    this.#events.set(key, copy(event));
    this.#runs.set(runKey, { ...run, last_event_sequence: event.sequence });
    return copy(event);
  }

  async listEvents(
    scope: ControlPlaneScope,
    runId: RunId,
    afterSequence = -1,
  ): Promise<HostedProgressEvent[]> {
    return [...this.#events.values()]
      .filter(
        (event) =>
          event.owner_id === scope.owner_id &&
          event.application_id === scope.application_id &&
          event.run_id === runId &&
          event.sequence > afterSequence,
      )
      .sort((left, right) => left.sequence - right.sequence)
      .map(copy);
  }

  async acquireLease(input: AcquireLeaseInput): Promise<Lease> {
    if (input.expires_at <= input.acquired_at) {
      throw invalidInput('lease expires_at must be after acquired_at');
    }
    const key = scopedKey(input, 'lease', input.resource_id);
    const current = this.#leases.get(key);
    if (current !== undefined && current.expires_at > input.acquired_at) {
      throw conflict(`resource ${input.resource_id} is already leased`);
    }
    const lease: Lease = {
      schema_version: 1,
      owner_id: input.owner_id,
      application_id: input.application_id,
      resource_id: input.resource_id,
      lease_owner_id: input.lease_owner_id,
      fencing_token: (current?.fencing_token ?? 0) + 1,
      acquired_at: input.acquired_at,
      expires_at: input.expires_at,
    };
    this.#leases.set(key, copy(lease));
    return copy(lease);
  }

  async renewLease(input: RenewLeaseInput): Promise<Lease> {
    if (input.expires_at <= input.observed_at) {
      throw invalidInput('renewed expires_at must be after observed_at');
    }
    const lease = this.#assertLease(input);
    const renewed = { ...lease, expires_at: input.expires_at };
    this.#leases.set(scopedKey(input, 'lease', input.resource_id), renewed);
    return copy(renewed);
  }

  async releaseLease(input: ReleaseLeaseInput): Promise<Lease> {
    const key = scopedKey(input, 'lease', input.resource_id);
    const lease = this.#leases.get(key);
    if (
      lease === undefined ||
      lease.lease_owner_id !== input.lease_owner_id ||
      lease.fencing_token !== input.fencing_token ||
      lease.expires_at <= input.released_at
    ) {
      throw leaseLost(`lease for ${input.resource_id} is no longer active`);
    }
    const released = { ...lease, expires_at: input.released_at };
    this.#leases.set(key, released);
    return copy(released);
  }

  async getLease(scope: ControlPlaneScope, resourceId: string): Promise<Lease | null> {
    const lease = this.#leases.get(scopedKey(scope, 'lease', resourceId));
    return lease === undefined ? null : copy(lease);
  }

  async claimIdempotency(
    record: IdempotencyRecord,
    observedAt: string,
  ): Promise<IdempotencyClaim> {
    if (record.expires_at <= observedAt) {
      throw invalidInput('idempotency record must expire after observedAt');
    }
    const key = scopedKey(record, 'idempotency', record.key);
    const current = this.#idempotency.get(key);
    if (current !== undefined && current.expires_at > observedAt) {
      if (current.operation !== record.operation || current.request_hash !== record.request_hash) {
        throw conflict(`idempotency key ${record.key} was used for a different request`);
      }
      return { acquired: false, record: copy(current) };
    }
    if (record.status !== 'in_progress') {
      throw invalidInput('a new idempotency claim must be in_progress');
    }
    this.#idempotency.set(key, copy(record));
    return { acquired: true, record: copy(record) };
  }

  async completeIdempotency(input: IdempotencyCompletionInput): Promise<IdempotencyRecord> {
    const key = scopedKey(input, 'idempotency', input.key);
    const current = this.#idempotency.get(key);
    this.#assertIdempotencyClaim(current, input.request_hash, input.claim_created_at, input.key);
    if (current.status === 'completed') {
      if (isDeepStrictEqual(current.response_artifact, input.response_artifact)) {
        return copy(current);
      }
      throw conflict(`idempotency key ${input.key} already has a different response`);
    }
    if (current.status !== 'in_progress') {
      throw conflict(`idempotency key ${input.key} is ${current.status}`);
    }
    const completed = { ...current, status: 'completed' as const, response_artifact: input.response_artifact };
    this.#idempotency.set(key, copy(completed));
    return copy(completed);
  }

  async failIdempotency(input: IdempotencyFailureInput): Promise<IdempotencyRecord> {
    const key = scopedKey(input, 'idempotency', input.key);
    const current = this.#idempotency.get(key);
    this.#assertIdempotencyClaim(current, input.request_hash, input.claim_created_at, input.key);
    if (current.status !== 'in_progress') {
      throw conflict(`idempotency key ${input.key} is ${current.status}`);
    }
    const failed = {
      ...current,
      status: 'failed' as const,
      expires_at: input.claim_created_at,
    };
    this.#idempotency.set(key, failed);
    return copy(failed);
  }

  async getIdempotency(
    scope: ControlPlaneScope,
    key: string,
  ): Promise<IdempotencyRecord | null> {
    const record = this.#idempotency.get(scopedKey(scope, 'idempotency', key));
    return record === undefined ? null : copy(record);
  }

  async createHitlRequest(request: HitlRequest, lease: LeaseGuard): Promise<HitlRequest> {
    assertSameScope(request, lease);
    this.#assertRunLease(lease, request.run_id);
    if (request.fencing_token !== lease.fencing_token) {
      throw leaseLost('HITL request fencing_token does not match the active lease');
    }
    if (request.status !== 'pending') {
      throw invalidInput('a new HITL request must be pending');
    }
    const headKey = hitlHeadKey(request, request.interaction_id);
    const currentRevision = this.#hitlHeads.get(headKey);
    const expectedRevision = currentRevision === undefined ? 1 : currentRevision + 1;
    if (request.revision !== expectedRevision) {
      throw staleRevision(`HITL revision must be ${expectedRevision}, not ${request.revision}`);
    }
    if (currentRevision !== undefined) {
      const previousKey = hitlKey(request, request.interaction_id, currentRevision);
      const previous = this.#hitlRequests.get(previousKey);
      if (previous === undefined || previous.run_id !== request.run_id) {
        throw conflict('an interaction_id cannot be reused for a different run');
      }
      if (previous.status === 'pending') {
        this.#hitlRequests.set(previousKey, { ...previous, status: 'superseded' });
      }
    }
    const key = hitlKey(request, request.interaction_id, request.revision);
    if (this.#hitlRequests.has(key)) {
      throw alreadyExists(`HITL revision ${request.revision} already exists`);
    }
    this.#hitlRequests.set(key, copy(request));
    this.#hitlHeads.set(headKey, request.revision);
    return copy(request);
  }

  async respondToHitl(response: HitlResponse): Promise<HitlResponse> {
    validateHitlResponse(response);
    const currentRevision = this.#hitlHeads.get(hitlHeadKey(response, response.interaction_id));
    if (currentRevision !== response.revision) {
      throw staleRevision(`HITL revision ${response.revision} is no longer current`);
    }
    const key = hitlKey(response, response.interaction_id, response.revision);
    const request = this.#hitlRequests.get(key);
    if (request === undefined || request.run_id !== response.run_id) {
      throw notFound('matching HITL request was not found');
    }
    if (this.#hitlResponses.has(key)) {
      throw alreadyExists('HITL request already has a response');
    }
    if (request.status !== 'pending') {
      throw conflict(`HITL request is ${request.status}`);
    }
    this.#hitlResponses.set(key, copy(response));
    this.#hitlRequests.set(key, {
      ...request,
      status: response.action === 'skip' ? 'skipped' : 'answered',
    });
    return copy(response);
  }

  async getHitlRequest(
    scope: ControlPlaneScope,
    interactionId: InteractionId,
    revision?: number,
  ): Promise<HitlRequest | null> {
    const resolvedRevision = revision ?? this.#hitlHeads.get(hitlHeadKey(scope, interactionId));
    if (resolvedRevision === undefined) {
      return null;
    }
    const request = this.#hitlRequests.get(hitlKey(scope, interactionId, resolvedRevision));
    return request === undefined ? null : copy(request);
  }

  async getHitlResponse(
    scope: ControlPlaneScope,
    interactionId: InteractionId,
    revision: number,
  ): Promise<HitlResponse | null> {
    const response = this.#hitlResponses.get(hitlKey(scope, interactionId, revision));
    return response === undefined ? null : copy(response);
  }

  async listPendingHitl(scope: ControlPlaneScope, runId: RunId): Promise<HitlRequest[]> {
    return [...this.#hitlRequests.values()]
      .filter(
        (request) =>
          request.owner_id === scope.owner_id &&
          request.application_id === scope.application_id &&
          request.run_id === runId &&
          request.status === 'pending' &&
          this.#hitlHeads.get(hitlHeadKey(request, request.interaction_id)) === request.revision,
      )
      .sort((left, right) => left.created_at.localeCompare(right.created_at))
      .map(copy);
  }

  #assertRunLease(guard: LeaseGuard, runId: RunId): Lease {
    if (guard.resource_id !== runLeaseResourceId(runId)) {
      throw invalidInput(`run mutations require lease resource ${runLeaseResourceId(runId)}`);
    }
    return this.#assertLease(guard);
  }

  #assertLease(guard: LeaseGuard): Lease {
    const lease = this.#leases.get(scopedKey(guard, 'lease', guard.resource_id));
    if (
      lease === undefined ||
      lease.lease_owner_id !== guard.lease_owner_id ||
      lease.fencing_token !== guard.fencing_token ||
      lease.expires_at <= guard.observed_at
    ) {
      throw leaseLost(`lease for ${guard.resource_id} is no longer active`);
    }
    return lease;
  }

  #assertIdempotencyClaim(
    current: IdempotencyRecord | undefined,
    requestHash: string,
    claimCreatedAt: string,
    key: string,
  ): asserts current is IdempotencyRecord {
    if (current === undefined) {
      throw notFound(`idempotency key ${key} was not found`);
    }
    if (current.request_hash !== requestHash || current.created_at !== claimCreatedAt) {
      throw conflict(`idempotency claim for ${key} is stale or belongs to another request`);
    }
  }
}
