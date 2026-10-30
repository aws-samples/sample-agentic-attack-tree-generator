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
  RunRecord,
  ResumeRunInput,
  RunControlIntent,
} from './models.js';

export interface ControlPlaneStore {
  createApplication(application: ApplicationRecord): Promise<ApplicationRecord>;
  getApplication(scope: ControlPlaneScope): Promise<ApplicationRecord | null>;
  listApplications(ownerId: UserId): Promise<ApplicationRecord[]>;
  updateApplication(application: ApplicationRecord, expectedRevision: number): Promise<ApplicationRecord>;

  putApplicationSettings(
    settings: ApplicationSettingsRecord,
    expectedRevision: number | null,
  ): Promise<ApplicationSettingsRecord>;
  getApplicationSettings(scope: ControlPlaneScope): Promise<ApplicationSettingsRecord | null>;
  putRunSettingsSnapshot(snapshot: RunSettingsSnapshot): Promise<RunSettingsSnapshot>;
  getRunSettingsSnapshot(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<RunSettingsSnapshot | null>;

  createRun(run: RunRecord): Promise<RunRecord>;
  createRunDispatch(
    run: RunRecord,
    settings: RunSettingsSnapshot,
  ): Promise<RunRecord>;
  getRun(scope: ControlPlaneScope, runId: RunId): Promise<RunRecord | null>;
  updateRun(run: RunRecord, expectedRevision: number, lease: LeaseGuard): Promise<RunRecord>;
  resumeRun(input: ResumeRunInput): Promise<RunRecord>;
  requestRunControl(intent: RunControlIntent): Promise<RunControlIntent>;
  getRunControl(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<RunControlIntent | null>;

  putCheckpoint(checkpoint: StageCheckpoint, lease: LeaseGuard): Promise<StageCheckpoint>;
  listCheckpoints(scope: ControlPlaneScope, runId: RunId): Promise<StageCheckpoint[]>;

  appendEvent(event: HostedProgressEvent, lease: LeaseGuard): Promise<HostedProgressEvent>;
  listEvents(
    scope: ControlPlaneScope,
    runId: RunId,
    afterSequence?: number,
  ): Promise<HostedProgressEvent[]>;

  acquireLease(input: AcquireLeaseInput): Promise<Lease>;
  renewLease(input: RenewLeaseInput): Promise<Lease>;
  releaseLease(input: ReleaseLeaseInput): Promise<Lease>;
  getLease(scope: ControlPlaneScope, resourceId: string): Promise<Lease | null>;

  claimIdempotency(record: IdempotencyRecord, observedAt: string): Promise<IdempotencyClaim>;
  completeIdempotency(input: IdempotencyCompletionInput): Promise<IdempotencyRecord>;
  failIdempotency(input: IdempotencyFailureInput): Promise<IdempotencyRecord>;
  getIdempotency(scope: ControlPlaneScope, key: string): Promise<IdempotencyRecord | null>;

  createHitlRequest(request: HitlRequest, lease: LeaseGuard): Promise<HitlRequest>;
  respondToHitl(response: HitlResponse): Promise<HitlResponse>;
  getHitlRequest(
    scope: ControlPlaneScope,
    interactionId: InteractionId,
    revision?: number,
  ): Promise<HitlRequest | null>;
  getHitlResponse(
    scope: ControlPlaneScope,
    interactionId: InteractionId,
    revision: number,
  ): Promise<HitlResponse | null>;
  listPendingHitl(scope: ControlPlaneScope, runId: RunId): Promise<HitlRequest[]>;
}
