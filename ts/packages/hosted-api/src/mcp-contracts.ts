import {
  ApplicationIdSchema,
  ArtifactIdSchema,
  CiaObjective,
  DataSensitivity,
  InteractionIdSchema,
  RunIdSchema,
  UserIdSchema,
} from '@threatforest/types';
import { z } from 'zod';

export const AGENTCORE_MCP_TARGET_NAME = 'ThreatForestTools';
export const AGENTCORE_MCP_TOOL_PREFIX = `${AGENTCORE_MCP_TARGET_NAME}___`;

const IdempotencyKeySchema = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[\x21-\x7e]+$/, 'must contain visible ASCII characters only');

const OwnerSchema = {
  owner_id: UserIdSchema,
};

const MutationSchema = {
  ...OwnerSchema,
  idempotency_key: IdempotencyKeySchema,
};

export const McpBusinessContextSchema = z
  .strictObject({
    description: z.string().max(16_384),
    regulatory_frameworks: z.array(z.string().min(1).max(256)).max(256),
    data_sensitivity: DataSensitivity,
    cia_priority: z.array(CiaObjective).length(3),
  })
  .refine((value) => new Set(value.cia_priority).size === 3, {
    message:
      'cia_priority must contain confidentiality, integrity, and availability exactly once',
    path: ['cia_priority'],
  });

export const ListApplicationsToolInputSchema = z.strictObject(OwnerSchema);

export const GetApplicationToolInputSchema = z.strictObject({
  ...OwnerSchema,
  application_id: ApplicationIdSchema,
});

export const CreateApplicationToolInputSchema = z.strictObject({
  ...MutationSchema,
  name: z.string().min(1).max(256),
  project_path: z.string().max(2048),
  business_context: McpBusinessContextSchema,
});

export const UpdateApplicationToolInputSchema = z
  .strictObject({
    ...MutationSchema,
    application_id: ApplicationIdSchema,
    name: z.string().min(1).max(256).optional(),
    project_path: z.string().max(2048).optional(),
    business_context: McpBusinessContextSchema.optional(),
  })
  .refine(
    (value) =>
      value.name !== undefined ||
      value.project_path !== undefined ||
      value.business_context !== undefined,
    {
      message:
        'At least one of name, project_path, or business_context is required.',
    },
  );

export const DeleteApplicationToolInputSchema = z.strictObject({
  ...MutationSchema,
  application_id: ApplicationIdSchema,
});

export const McpRunStatusSchema = z.enum([
  'pending',
  'running',
  'paused',
  'complete',
  'failed',
  'stopped',
]);

export const ListRunsToolInputSchema = z.strictObject({
  ...OwnerSchema,
  statuses: z.array(McpRunStatusSchema).max(6).optional(),
});

export const GetRunToolInputSchema = z.strictObject({
  ...OwnerSchema,
  run_id: RunIdSchema,
});

export const StartRunToolInputSchema = z
  .strictObject({
    ...MutationSchema,
    app_id: ApplicationIdSchema,
    source_artifact_ids: z.array(ArtifactIdSchema).max(10_000).optional(),
    threat_artifact_id: ArtifactIdSchema.nullable().default(null),
    project_path: z.string().max(2048).default(''),
    threat_source: z.enum(['auto', 'file']).default('auto'),
    threat_file_path: z.string().max(2048).nullable().default(null),
    frameworks: z.array(z.string().min(1).max(128)).min(1).max(128).nullable().default(null),
    resume_run_dir: z.string().max(2048).nullable().default(null),
    skip_nodes: z.array(z.string().min(1).max(128)).max(128).default([]),
  })
  .refine(
    (value) =>
      value.threat_source !== 'file' || value.threat_file_path !== null,
    {
      message: 'threat_file_path is required when threat_source is file.',
      path: ['threat_file_path'],
    },
  );

const RunMutationSchema = {
  ...MutationSchema,
  run_id: RunIdSchema,
};

export const PauseRunToolInputSchema = z.strictObject(RunMutationSchema);
export const StopRunToolInputSchema = z.strictObject(RunMutationSchema);
export const ResumeRunToolInputSchema = z.strictObject(RunMutationSchema);

export const ListPendingInteractionsToolInputSchema = z.strictObject({
  ...OwnerSchema,
  run_id: RunIdSchema,
});

const InteractionMutationSchema = {
  ...RunMutationSchema,
  interaction_id: InteractionIdSchema,
  revision: z.number().int().positive(),
};

export const RespondToInteractionToolInputSchema = z.strictObject({
  ...InteractionMutationSchema,
  text: z.string().min(1).max(1_000_000),
});

export const SkipInteractionToolInputSchema = z.strictObject(
  InteractionMutationSchema,
);

export const MCP_TOOL_REGISTRY = {
  list_applications: ListApplicationsToolInputSchema,
  get_application: GetApplicationToolInputSchema,
  create_application: CreateApplicationToolInputSchema,
  update_application: UpdateApplicationToolInputSchema,
  delete_application: DeleteApplicationToolInputSchema,
  list_runs: ListRunsToolInputSchema,
  get_run: GetRunToolInputSchema,
  start_run: StartRunToolInputSchema,
  pause_run: PauseRunToolInputSchema,
  stop_run: StopRunToolInputSchema,
  resume_run: ResumeRunToolInputSchema,
  list_pending_interactions: ListPendingInteractionsToolInputSchema,
  respond_to_interaction: RespondToInteractionToolInputSchema,
  skip_interaction: SkipInteractionToolInputSchema,
} as const;

export type McpToolName = keyof typeof MCP_TOOL_REGISTRY;

export const MCP_TOOL_NAMES = Object.freeze(
  Object.keys(MCP_TOOL_REGISTRY) as McpToolName[],
);

export function isMcpToolName(value: string): value is McpToolName {
  return Object.hasOwn(MCP_TOOL_REGISTRY, value);
}

export type ListApplicationsToolInput = z.infer<
  typeof ListApplicationsToolInputSchema
>;
export type GetApplicationToolInput = z.infer<
  typeof GetApplicationToolInputSchema
>;
export type CreateApplicationToolInput = z.infer<
  typeof CreateApplicationToolInputSchema
>;
export type UpdateApplicationToolInput = z.infer<
  typeof UpdateApplicationToolInputSchema
>;
export type DeleteApplicationToolInput = z.infer<
  typeof DeleteApplicationToolInputSchema
>;
export type ListRunsToolInput = z.infer<typeof ListRunsToolInputSchema>;
export type GetRunToolInput = z.infer<typeof GetRunToolInputSchema>;
export type StartRunToolInput = z.infer<typeof StartRunToolInputSchema>;
export type PauseRunToolInput = z.infer<typeof PauseRunToolInputSchema>;
export type StopRunToolInput = z.infer<typeof StopRunToolInputSchema>;
export type ResumeRunToolInput = z.infer<typeof ResumeRunToolInputSchema>;
export type ListPendingInteractionsToolInput = z.infer<
  typeof ListPendingInteractionsToolInputSchema
>;
export type RespondToInteractionToolInput = z.infer<
  typeof RespondToInteractionToolInputSchema
>;
export type SkipInteractionToolInput = z.infer<
  typeof SkipInteractionToolInputSchema
>;

type McpBusinessContext = z.infer<typeof McpBusinessContextSchema>;
type ReadonlyMcpBusinessContext = Omit<
  McpBusinessContext,
  'regulatory_frameworks' | 'cia_priority'
> & {
  readonly regulatory_frameworks: readonly string[];
  readonly cia_priority: readonly McpBusinessContext['cia_priority'][number][];
};

export type CreateApplicationPayload = Omit<
  CreateApplicationToolInput,
  'owner_id' | 'idempotency_key' | 'business_context'
> & {
  readonly business_context: ReadonlyMcpBusinessContext;
};
export type UpdateApplicationPayload = Omit<
  UpdateApplicationToolInput,
  'owner_id' | 'idempotency_key' | 'application_id' | 'business_context'
> & {
  readonly business_context?: ReadonlyMcpBusinessContext;
};
export type StartRunPayload = Omit<
  StartRunToolInput,
  'owner_id' | 'idempotency_key'
>;
