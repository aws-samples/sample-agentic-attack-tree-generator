import type {
  ApplicationId,
  ArtifactId,
  ArtifactRef,
  HitlInteractionKind,
  HitlRequest,
  HitlResponse,
  RunId,
  RunSettingsSnapshot,
  StageCheckpoint,
  UserId,
} from '@threatforest/types';
import type {
  ControlPlaneScope,
  ControlPlaneStore,
  RunRecord,
} from '@threatforest/control-plane';
import type { HostedTelemetry } from './telemetry.js';

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export interface AuthenticatedPrincipal {
  subject: string;
  issuer: string;
  userId: UserId;
  claims: Readonly<Record<string, unknown>>;
}

export interface RuntimeHttpRequest {
  method: string;
  path: string;
  headers?: Readonly<Record<string, string | string[] | undefined>>;
  body?: unknown;
  context?: unknown;
}

export interface RuntimeHttpResponse {
  statusCode: number;
  headers: Readonly<Record<string, string>>;
  body: string;
}

export interface PrincipalResolver {
  resolve(request: RuntimeHttpRequest): Promise<AuthenticatedPrincipal>;
}

export interface ActorIdDeriver {
  deriveActorId(principal: AuthenticatedPrincipal, applicationId: ApplicationId): Promise<string>;
}

export interface RunSettingsInput {
  provider: string;
  model_id: string;
  aws_region?: string | null;
  model_parameters: Record<string, string | number | boolean>;
  frameworks: string[];
  embeddings_model: string;
}

export interface StartRunInput {
  applicationId: ApplicationId;
  sourceArtifactIds: ArtifactId[];
  threatArtifactId: ArtifactId | null;
  projectPath: string | null;
  threatFilePath: string | null;
  settings: RunSettingsInput;
  idempotencyKey: string;
}

export interface TranscriptWriteInput extends ControlPlaneScope {
  run_id: RunId;
  interaction_id: string;
  revision: number;
  stage_id: string;
  trace_id: string;
  idempotency_key: string;
  transcript: unknown;
}

export interface ArtifactStore {
  putTranscript(input: TranscriptWriteInput): Promise<ArtifactRef>;
}

export interface StageDefinition {
  id: string;
  version: number;
  hitlKind: HitlInteractionKind | null;
  usesModel: boolean;
}

export interface HitlExchange {
  request: HitlRequest;
  response: HitlResponse;
}

export interface StageExecutionContext {
  scope: ControlPlaneScope;
  run: RunRecord;
  settings: RunSettingsSnapshot;
  stage: StageDefinition;
  checkpoint: StageCheckpoint;
  actorId: string;
  completedStageIds: readonly string[];
  hitlHistory: readonly HitlExchange[];
  response: HitlResponse | null;
  signal: AbortSignal;
  assertLease(): Promise<void>;
}

export interface CompletedStageResult {
  status: 'completed';
  outputArtifacts?: readonly ArtifactRef[];
}

export interface AwaitingInputStageResult {
  status: 'awaiting_input';
  reason: Readonly<Record<string, unknown>>;
  transcript: unknown;
  outputArtifacts?: readonly ArtifactRef[];
}

export type StageExecutionResult = CompletedStageResult | AwaitingInputStageResult;

export interface StageExecutor {
  execute(context: StageExecutionContext): Promise<StageExecutionResult>;
  recover?(
    context: StageExecutionContext,
    checkpoint: StageCheckpoint,
  ): Promise<StageExecutionResult | null>;
}

export interface StageOutputPublisher {
  publish(
    context: StageExecutionContext,
    runDir: string,
    repoPath?: string,
  ): Promise<readonly ArtifactRef[]>;
}

export type BoundaryName = 'completed' | 'awaiting_input' | 'failed' | 'busy';

export interface BoundaryResult {
  boundary: BoundaryName;
  run: RunRecord;
  actor_id: string;
  interaction: HitlRequest | null;
}

export interface DurableBoundaryExecutorOptions {
  store: ControlPlaneStore;
  artifactStore: ArtifactStore;
  stageExecutor: StageExecutor;
  telemetry?: HostedTelemetry;
  stagePlan?: readonly StageDefinition[];
  clock?: Clock;
  leaseDurationMs?: number;
  leaseHeartbeatMs?: number;
  workerId?: string;
}
