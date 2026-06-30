/**
 * Server API contract — mirrors `src/server/models.py`.
 *
 * This is the frozen HTTP/WS contract shared by the TS server (WS-4) and the
 * Next.js UI (WS-6). Validators that the Python side enforces (cia_priority
 * shape, threat_file requirement, mitigation comment) are reproduced as Zod
 * refinements so both ends reject the same payloads.
 */
import { z } from 'zod';

export const CiaObjective = z.enum(['confidentiality', 'integrity', 'availability']);
export type CiaObjectiveT = z.infer<typeof CiaObjective>;

export const CIA_DEFAULT_ORDER: CiaObjectiveT[] = [
  'confidentiality',
  'integrity',
  'availability',
];

export const DataSensitivity = z.enum([
  'public',
  'internal',
  'confidential',
  'highly_confidential',
  'pii',
  'phi',
  'regulated_financial',
  'unknown',
]);

export const BusinessContextSchema = z
  .object({
    description: z.string(),
    regulatory_frameworks: z.array(z.string()),
    data_sensitivity: DataSensitivity,
    cia_priority: z
      .array(CiaObjective)
      .default(() => [...CIA_DEFAULT_ORDER]),
  })
  .refine(
    (v) =>
      v.cia_priority.length === 3 &&
      new Set(v.cia_priority).size === 3 &&
      v.cia_priority.every((o) => CIA_DEFAULT_ORDER.includes(o)),
    {
      message:
        'cia_priority must contain confidentiality, integrity, and availability exactly once',
      path: ['cia_priority'],
    },
  );
export type BusinessContext = z.infer<typeof BusinessContextSchema>;

export const ApplicationSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  project_path: z.string(),
  business_context: BusinessContextSchema,
  created_at: z.string(),
  updated_at: z.string(),
  run_dir_name: z.string(),
});
export type Application = z.infer<typeof ApplicationSchema>;

export const ApplicationCreateRequestSchema = z.object({
  name: z.string(),
  project_path: z.string(),
  business_context: BusinessContextSchema,
});
export type ApplicationCreateRequest = z.infer<typeof ApplicationCreateRequestSchema>;

export const ApplicationUpdateRequestSchema = z
  .object({
    name: z.string().nullable().default(null),
    business_context: BusinessContextSchema.nullable().default(null),
    project_path: z.string().nullable().default(null),
  })
  .refine(
    (v) => v.name !== null || v.business_context !== null || v.project_path !== null,
    { message: "At least one of 'name', 'business_context', or 'project_path' must be provided" },
  );
export type ApplicationUpdateRequest = z.infer<typeof ApplicationUpdateRequestSchema>;

export const ApplicationSummarySchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  version_count: z.number().int(),
  last_run_date: z.string(),
  business_context: BusinessContextSchema.nullable().default(null),
  imported: z.boolean().default(false),
  imported_from: z.string().nullable().default(null),
});
export type ApplicationSummary = z.infer<typeof ApplicationSummarySchema>;

export const VersionSummarySchema = z.object({
  id: z.string(),
  run_date: z.string(),
  status: z.string(),
  threat_count: z.number().int(),
  high_severity_count: z.number().int().default(0),
  categories: z.array(z.string()),
  display_name: z.string().default(''),
  run_id: z.string().nullable().default(null),
});
export type VersionSummary = z.infer<typeof VersionSummarySchema>;

export const ThreatSource = z.enum(['auto', 'file']);

export const RunConfigSchema = z
  .object({
    project_path: z.string(),
    threat_source: ThreatSource.default('auto'),
    threat_file_path: z.string().nullable().default(null),
    frameworks: z.array(z.string()).nullable().default(null),
    resume_run_dir: z.string().nullable().default(null),
    skip_nodes: z.array(z.string()).default([]),
    app_id: z.string().nullable().default(null),
  })
  .refine((v) => !(v.threat_source === 'file' && !v.threat_file_path), {
    message: "threat_file_path is required when threat_source is 'file'",
    path: ['threat_file_path'],
  });
export type RunConfig = z.infer<typeof RunConfigSchema>;

export const RunResponseSchema = z.object({ run_id: z.string() });
export type RunResponse = z.infer<typeof RunResponseSchema>;

export const ResumeResponseSchema = z.object({ new_run_id: z.string() });
export type ResumeResponse = z.infer<typeof ResumeResponseSchema>;

export const InteractionResponseSchema = z.object({
  text: z.string().nullable().default(null),
});
export type InteractionResponse = z.infer<typeof InteractionResponseSchema>;

export const DirectoryEntrySchema = z.object({
  name: z.string(),
  entry_type: z.string(), // "file" | "directory"
  size: z.number().int().nullable().default(null),
  modified: z.string().nullable().default(null),
});
export type DirectoryEntry = z.infer<typeof DirectoryEntrySchema>;

export const DirectoryListingSchema = z.object({
  current_path: z.string(),
  parent_path: z.string().nullable(),
  entries: z.array(DirectoryEntrySchema),
});
export type DirectoryListing = z.infer<typeof DirectoryListingSchema>;

export const ConfigResponseSchema = z.object({
  model_provider: z.string(),
  model_id: z.string(),
  embeddings_model: z.string(),
  default_browse_path: z.string(),
  aws_profile: z.string().nullable().default(null),
});
export type ConfigResponse = z.infer<typeof ConfigResponseSchema>;

export const RunStateSchema = z.object({
  run_id: z.string(),
  // pending | running | pausing | paused | stopped | complete | failed
  status: z.string(),
  config: RunConfigSchema,
  started_at: z.string(),
  completed_at: z.string().nullable().default(null),
  output_dir: z.string().nullable().default(null),
  error: z.string().nullable().default(null),
  paused_at_stage: z.string().nullable().default(null),
  paused_at: z.string().nullable().default(null),
});
export type RunState = z.infer<typeof RunStateSchema>;

export const ProvidersResponseSchema = z.object({ providers: z.array(z.string()) });
export type ProvidersResponse = z.infer<typeof ProvidersResponseSchema>;

export const ConfigTestRequestSchema = z.object({
  provider: z.string(),
  model_id: z.string(),
  aws_profile: z.string().nullable().default(null),
  aws_region: z.string().nullable().default(null),
  api_key: z.string().nullable().default(null),
});
export type ConfigTestRequest = z.infer<typeof ConfigTestRequestSchema>;

export const ConfigTestResponseSchema = z.object({
  success: z.boolean(),
  message: z.string(),
});
export type ConfigTestResponse = z.infer<typeof ConfigTestResponseSchema>;

export const ConfigSaveRequestSchema = z.object({
  provider: z.string(),
  model_id: z.string(),
  aws_profile: z.string().nullable().default(null),
});
export type ConfigSaveRequest = z.infer<typeof ConfigSaveRequestSchema>;

export const LangfuseConfigResponseSchema = z.object({
  enabled: z.boolean().default(false),
  public_key: z.string().nullable().default(null),
  secret_key_configured: z.boolean().default(false),
  host: z.string().default('https://cloud.langfuse.com'),
});
export type LangfuseConfigResponse = z.infer<typeof LangfuseConfigResponseSchema>;

export const LangfuseConfigSaveRequestSchema = z.object({
  enabled: z.boolean(),
  public_key: z.string().nullable().default(null),
  secret_key: z.string().nullable().default(null),
  host: z.string().default('https://cloud.langfuse.com'),
});
export type LangfuseConfigSaveRequest = z.infer<typeof LangfuseConfigSaveRequestSchema>;

// --- Mitigation overrides (M3 v1) ------------------------------------------
export const MitigationStatus = z.enum([
  'not_relevant',
  'already_implemented',
  'in_progress',
  'wont_do',
  'accepted_risk',
]);
export type MitigationStatusT = z.infer<typeof MitigationStatus>;

export const MitigationOverrideSchema = z.object({
  status: MitigationStatus,
  comment: z.string().refine((c) => c.trim().length > 0, {
    message: 'comment is required when setting a mitigation status',
  }),
  updated_at: z.string(), // ISO 8601, set server-side
});
export type MitigationOverride = z.infer<typeof MitigationOverrideSchema>;

export const MitigationOverrideRequestSchema = z.object({
  status: MitigationStatus,
  comment: z.string().refine((c) => c.trim().length > 0, {
    message: 'comment is required when setting a mitigation status',
  }),
});
export type MitigationOverrideRequest = z.infer<typeof MitigationOverrideRequestSchema>;

// --- WebSocket progress event ----------------------------------------------
// Shape emitted on /ws/runs/{id}/progress. The legacy server streams loosely-
// typed progress dicts; this captures the fields the UI reads (see WS-4/WS-6).
export const ProgressEventSchema = z.object({
  stage: z.string().optional(),
  status: z.string().optional(),
  progress: z.number().optional(),
  message: z.string().optional(),
  error: z.string().nullable().optional(),
  heartbeat: z.boolean().optional(),
});
export type ProgressEvent = z.infer<typeof ProgressEventSchema>;
