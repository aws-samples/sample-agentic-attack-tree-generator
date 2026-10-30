import { z } from 'zod';
import { BusinessContextSchema } from './api.js';

const OpaqueIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/, 'must be an opaque identifier');

export const UserIdSchema = OpaqueIdSchema.brand<'UserId'>();
export const ApplicationIdSchema = OpaqueIdSchema.brand<'ApplicationId'>();
export const RunIdSchema = OpaqueIdSchema.brand<'RunId'>();
export const ArtifactIdSchema = OpaqueIdSchema.brand<'ArtifactId'>();
export const UploadIdSchema = OpaqueIdSchema.brand<'UploadId'>();
export const InteractionIdSchema = OpaqueIdSchema.brand<'InteractionId'>();

export type UserId = z.infer<typeof UserIdSchema>;
export type ApplicationId = z.infer<typeof ApplicationIdSchema>;
export type RunId = z.infer<typeof RunIdSchema>;
export type ArtifactId = z.infer<typeof ArtifactIdSchema>;
export type UploadId = z.infer<typeof UploadIdSchema>;
export type InteractionId = z.infer<typeof InteractionIdSchema>;

export const ArtifactKindSchema = z.enum([
  'source',
  'normalized_evidence',
  'checkpoint',
  'report',
  'export',
  'transcript',
  'threat_input',
]);
export type ArtifactKind = z.infer<typeof ArtifactKindSchema>;

export const ArtifactRefSchema = z.object({
  artifact_id: ArtifactIdSchema,
  kind: ArtifactKindSchema,
  version: z.number().int().positive(),
  content_type: z.string().min(1).max(255),
  size_bytes: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  created_at: z.iso.datetime(),
});
export type ArtifactRef = z.infer<typeof ArtifactRefSchema>;

export const UploadStatusSchema = z.enum([
  'pending',
  'uploading',
  'uploaded',
  'normalizing',
  'ready',
  'failed',
  'cancelled',
]);
export type UploadStatus = z.infer<typeof UploadStatusSchema>;

export const UploadPartSchema = z.object({
  part_number: z.number().int().min(1).max(10_000),
  size_bytes: z.number().int().positive(),
  etag: z.string().min(1).max(1024).nullable().default(null),
  checksum_sha256: z.string().min(1).max(128).nullable().default(null),
});
export type UploadPart = z.infer<typeof UploadPartSchema>;

export const UploadManifestSchema = z.object({
  schema_version: z.literal(1),
  owner_id: UserIdSchema,
  upload_id: UploadIdSchema,
  application_id: ApplicationIdSchema,
  filename: z.string().min(1).max(1024),
  content_type: z.string().min(1).max(255),
  size_bytes: z.number().int().nonnegative(),
  status: UploadStatusSchema,
  parts: z.array(UploadPartSchema).max(10_000).default([]),
  source_artifact: ArtifactRefSchema.nullable().default(null),
  normalized_artifacts: z.array(ArtifactRefSchema).default([]),
  created_at: z.iso.datetime(),
  updated_at: z.iso.datetime(),
  failure_reason: z.string().max(4096).nullable().default(null),
});
export type UploadManifest = z.infer<typeof UploadManifestSchema>;

export const CheckpointStatusSchema = z.enum([
  'started',
  'completed',
  'failed',
  'awaiting_input',
  'cancelled',
]);
export type CheckpointStatus = z.infer<typeof CheckpointStatusSchema>;

export const StageCheckpointSchema = z.object({
  schema_version: z.literal(1),
  owner_id: UserIdSchema,
  application_id: ApplicationIdSchema,
  run_id: RunIdSchema,
  stage_id: z.string().min(1).max(128),
  stage_version: z.number().int().positive(),
  attempt: z.number().int().positive(),
  fencing_token: z.number().int().positive(),
  idempotency_key: z.string().min(1).max(512),
  trace_id: z.string().min(16).max(64),
  status: CheckpointStatusSchema,
  input_artifacts: z.array(ArtifactRefSchema).default([]),
  output_artifacts: z.array(ArtifactRefSchema).default([]),
  model_id: z.string().max(512).nullable().default(null),
  config_hash: z.string().regex(/^[a-f0-9]{64}$/),
  started_at: z.iso.datetime(),
  completed_at: z.iso.datetime().nullable().default(null),
  error_code: z.string().max(128).nullable().default(null),
  error_message: z.string().max(4096).nullable().default(null),
});
export type StageCheckpoint = z.infer<typeof StageCheckpointSchema>;

export const HostedProgressEventSchema = z.object({
  schema_version: z.literal(1),
  owner_id: UserIdSchema,
  application_id: ApplicationIdSchema,
  run_id: RunIdSchema,
  sequence: z.number().int().nonnegative(),
  event_id: z.string().min(1).max(128),
  trace_id: z.string().min(16).max(64),
  type: z.string().min(1).max(128),
  stage: z.string().max(128).nullable().default(null),
  percentage: z.number().min(0).max(100).nullable().default(null),
  message: z.string().max(8192).nullable().default(null),
  payload: z.record(z.string(), z.unknown()).default({}),
  emitted_at: z.iso.datetime(),
});
export type HostedProgressEvent = z.infer<typeof HostedProgressEventSchema>;

export const RunLogContentSchema = z.object({
  kind: z.enum(['request', 'response', 'reasoning', 'tool_input', 'tool_result', 'error']),
  text: z.string(),
  truncated: z.boolean().default(false),
  role: z.enum(['user', 'assistant', 'tool']).optional(),
});
export type RunLogContent = z.infer<typeof RunLogContentSchema>;

export const RunLogEntrySchema = z.object({
  id: z.string(),
  run_id: RunIdSchema,
  trace_id: z.string(),
  span_id: z.string(),
  parent_span_id: z.string().nullable().default(null),
  stage: z.string().nullable().default(null),
  category: z.enum(['stage', 'agent', 'model', 'tool', 'hitl', 'error']),
  title: z.string(),
  summary: z.string(),
  status: z.enum(['running', 'completed', 'error']),
  started_at: z.iso.datetime(),
  completed_at: z.iso.datetime().nullable().default(null),
  duration_ms: z.number().nonnegative().nullable().default(null),
  details: z.record(z.string(), z.unknown()).default({}),
  agent_id: z.string().nullable().optional(),
  agent_name: z.string().nullable().optional(),
  invocation_id: z.string().nullable().optional(),
  content: z.array(RunLogContentSchema).optional(),
});
export type RunLogEntry = z.infer<typeof RunLogEntrySchema>;

export const RunLogsResponseSchema = z.object({
  run_id: RunIdSchema,
  entries: z.array(RunLogEntrySchema),
  next_token: z.string().nullable().default(null),
  source: z.literal('agentcore_cloudwatch'),
  window_end: z.iso.datetime().optional(),
});
export type RunLogsResponse = z.infer<typeof RunLogsResponseSchema>;

export const LeaseSchema = z.object({
  schema_version: z.literal(1),
  owner_id: UserIdSchema,
  application_id: ApplicationIdSchema,
  resource_id: z.string().min(1).max(512),
  lease_owner_id: z.string().min(1).max(256),
  fencing_token: z.number().int().positive(),
  acquired_at: z.iso.datetime(),
  expires_at: z.iso.datetime(),
});
export type Lease = z.infer<typeof LeaseSchema>;

export const IdempotencyRecordSchema = z.object({
  schema_version: z.literal(1),
  owner_id: UserIdSchema,
  application_id: ApplicationIdSchema,
  key: z.string().min(1).max(512),
  operation: z.string().min(1).max(128),
  request_hash: z.string().regex(/^[a-f0-9]{64}$/),
  status: z.enum(['in_progress', 'completed', 'failed']),
  response_artifact: ArtifactRefSchema.nullable().default(null),
  created_at: z.iso.datetime(),
  expires_at: z.iso.datetime(),
});
export type IdempotencyRecord = z.infer<typeof IdempotencyRecordSchema>;

export const HitlInteractionKindSchema = z.enum([
  'scanner_review',
  'interviewer',
  'threat_review',
  'mapping_review',
  'mitigation_review',
]);
export type HitlInteractionKind = z.infer<typeof HitlInteractionKindSchema>;

export const HitlInteractionStatusSchema = z.enum([
  'pending',
  'answered',
  'skipped',
  'superseded',
  'cancelled',
]);
export type HitlInteractionStatus = z.infer<typeof HitlInteractionStatusSchema>;

export const HitlRequestSchema = z.object({
  schema_version: z.literal(1),
  owner_id: UserIdSchema,
  application_id: ApplicationIdSchema,
  interaction_id: InteractionIdSchema,
  run_id: RunIdSchema,
  stage_id: z.string().min(1).max(128),
  kind: HitlInteractionKindSchema,
  revision: z.number().int().positive(),
  fencing_token: z.number().int().positive(),
  trace_id: z.string().min(16).max(64),
  status: HitlInteractionStatusSchema,
  reason: z.record(z.string(), z.unknown()),
  transcript_artifact: ArtifactRefSchema.nullable().default(null),
  created_at: z.iso.datetime(),
  expires_at: z.iso.datetime().nullable().default(null),
});
export type HitlRequest = z.infer<typeof HitlRequestSchema>;

export const HitlResponseSchema = z.object({
  schema_version: z.literal(1),
  owner_id: UserIdSchema,
  application_id: ApplicationIdSchema,
  interaction_id: InteractionIdSchema,
  run_id: RunIdSchema,
  revision: z.number().int().positive(),
  action: z.enum(['submit', 'skip']),
  text: z.string().max(1_000_000).nullable().default(null),
  submitted_at: z.iso.datetime(),
});
export type HitlResponse = z.infer<typeof HitlResponseSchema>;

export const RunSettingsSnapshotSchema = z.object({
  schema_version: z.literal(1),
  owner_id: UserIdSchema,
  application_id: ApplicationIdSchema,
  run_id: RunIdSchema,
  provider: z.string().min(1).max(128),
  model_id: z.string().min(1).max(512),
  aws_region: z.string().min(3).max(64).nullable().optional(),
  model_parameters: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])),
  frameworks: z.array(z.string().min(1).max(128)).min(1),
  embeddings_model: z.string().min(1).max(512),
  // Optional only for runs created before business context was snapshotted.
  business_context: BusinessContextSchema.optional(),
  business_context_updated_at: z.iso.datetime().optional(),
  config_hash: z.string().regex(/^[a-f0-9]{64}$/),
  created_at: z.iso.datetime(),
});
export type RunSettingsSnapshot = z.infer<typeof RunSettingsSnapshotSchema>;

export const HostedRunInputSchema = z
  .object({
    application_id: ApplicationIdSchema,
    source_artifact_ids: z.array(ArtifactIdSchema).default([]),
    threat_artifact_id: ArtifactIdSchema.nullable().default(null),
    // Local-only compatibility fields. Hosted callers use opaque IDs above.
    project_path: z.string().nullable().default(null),
    threat_file_path: z.string().nullable().default(null),
  })
  .refine(
    (value) =>
      value.source_artifact_ids.length > 0 ||
      (value.project_path !== null && value.project_path.trim().length > 0),
    {
      message: 'source_artifact_ids or project_path is required',
      path: ['source_artifact_ids'],
    },
  );
export type HostedRunInput = z.infer<typeof HostedRunInputSchema>;
