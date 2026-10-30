import type {
  ApplicationId,
  ArtifactId,
  HitlRequest,
  HostedProgressEvent,
  RunId,
  RunSettingsSnapshot,
  StageCheckpoint,
  UserId,
} from '@threatforest/types';

export interface ControlPlaneScope {
  owner_id: UserId;
  application_id: ApplicationId;
}

export interface ApplicationRecord extends ControlPlaneScope {
  schema_version: 1;
  name: string;
  description: string | null;
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface ApplicationSettingsRecord extends ControlPlaneScope {
  schema_version: 1;
  revision: number;
  provider: string;
  model_id: string;
  aws_region?: string | null;
  model_parameters: Record<string, string | number | boolean>;
  frameworks: string[];
  embeddings_model: string;
  config_hash: string;
  updated_at: string;
}

export type RunStatus =
  | 'queued'
  | 'running'
  | 'awaiting_input'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface RunRecord extends ControlPlaneScope {
  /** Human label; never used as a storage key or authorization identifier. */
  display_name?: string;
  schema_version: 1;
  run_id: RunId;
  status: RunStatus;
  source_artifact_ids: ArtifactId[];
  threat_artifact_id: ArtifactId | null;
  current_stage_id: string | null;
  trace_id: string;
  revision: number;
  last_event_sequence: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  error_code: string | null;
  error_message: string | null;
}

export interface RunControlIntent extends ControlPlaneScope {
  run_id: RunId;
  action: 'pause' | 'stop';
  requested_at: string;
}

export interface ResumeRunInput extends ControlPlaneScope {
  run_id: RunId;
  expected_revision: number;
  expected_status: 'failed' | 'cancelled' | 'awaiting_input';
  resumed_at: string;
}

export interface LeaseGuard extends ControlPlaneScope {
  resource_id: string;
  lease_owner_id: string;
  fencing_token: number;
  observed_at: string;
}

export interface AcquireLeaseInput extends ControlPlaneScope {
  resource_id: string;
  lease_owner_id: string;
  acquired_at: string;
  expires_at: string;
}

export interface RenewLeaseInput extends LeaseGuard {
  expires_at: string;
}

export interface ReleaseLeaseInput extends Omit<LeaseGuard, 'observed_at'> {
  released_at: string;
}

export interface IdempotencyClaim {
  acquired: boolean;
  record: import('@threatforest/types').IdempotencyRecord;
}

export interface IdempotencyCompletionInput extends ControlPlaneScope {
  key: string;
  request_hash: string;
  claim_created_at: string;
  response_artifact: import('@threatforest/types').ArtifactRef | null;
}

export interface IdempotencyFailureInput extends ControlPlaneScope {
  key: string;
  request_hash: string;
  claim_created_at: string;
}

export interface RunReconstruction {
  run: RunRecord;
  settings: RunSettingsSnapshot;
  checkpoints: StageCheckpoint[];
  events: HostedProgressEvent[];
  pending_interactions: HitlRequest[];
}
