import { badRequest, mapError } from '../errors.js';
import {
  AGENTCORE_MCP_TOOL_PREFIX,
  CreateApplicationToolInputSchema,
  DeleteApplicationToolInputSchema,
  GetApplicationToolInputSchema,
  GetRunToolInputSchema,
  ListApplicationsToolInputSchema,
  ListPendingInteractionsToolInputSchema,
  ListRunsToolInputSchema,
  PauseRunToolInputSchema,
  RespondToInteractionToolInputSchema,
  ResumeRunToolInputSchema,
  SkipInteractionToolInputSchema,
  StartRunToolInputSchema,
  StopRunToolInputSchema,
  UpdateApplicationToolInputSchema,
  isMcpToolName,
  type McpToolName,
} from '../mcp-contracts.js';
import type { HostedMcpServices } from '../mcp.js';
import {
  getHostedMcpComposition,
  readHostedMcpLambdaEnvironment,
  type HostedMcpLambdaEnvironment,
} from '../composition.js';

export interface AgentCoreLambdaContext {
  awsRequestId?: string;
  clientContext?: {
    custom?: Record<string, unknown>;
  } | null;
}

export interface AgentCoreMcpSuccess {
  ok: true;
  tool: McpToolName;
  result: unknown;
}

export interface AgentCoreMcpFailure {
  ok: false;
  error: {
    status: number;
    code: string;
    message: string;
  };
}

export type AgentCoreMcpResponse =
  | AgentCoreMcpSuccess
  | AgentCoreMcpFailure;

export interface McpStructuredLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export interface AgentCoreMcpHandlerOptions {
  services: HostedMcpServices;
  environment: HostedMcpLambdaEnvironment;
  logger?: McpStructuredLogger;
}

interface AgentCoreInvocationMetadata {
  messageVersion: '1.0';
  awsRequestId: string;
  mcpMessageId: string;
  gatewayId: string;
  targetId: string;
  toolName: McpToolName;
}

function requiredMetadata(
  custom: Record<string, unknown>,
  name: string,
): string {
  const value = custom[name];
  if (typeof value !== 'string' || value.trim() === '') {
    throw badRequest(`AgentCore context metadata ${name} is required.`);
  }
  return value;
}

function invocationMetadata(
  context: AgentCoreLambdaContext,
  environment: HostedMcpLambdaEnvironment,
): AgentCoreInvocationMetadata {
  const custom = context.clientContext?.custom;
  if (custom === undefined) {
    throw badRequest('AgentCore clientContext.custom metadata is required.');
  }
  const messageVersion = requiredMetadata(
    custom,
    'bedrockAgentCoreMessageVersion',
  );
  if (messageVersion !== '1.0') {
    throw badRequest('Unsupported AgentCore message version.');
  }
  const gatewayId = requiredMetadata(custom, 'bedrockAgentCoreGatewayId');
  const targetId = requiredMetadata(custom, 'bedrockAgentCoreTargetId');
  if (gatewayId !== environment.gatewayId) {
    throw badRequest('AgentCore gateway ID does not match this Lambda target.');
  }
  if (
    environment.targetId !== undefined &&
    targetId !== environment.targetId
  ) {
    throw badRequest('AgentCore target ID does not match this Lambda target.');
  }
  const qualifiedToolName = requiredMetadata(
    custom,
    'bedrockAgentCoreToolName',
  );
  if (!qualifiedToolName.startsWith(AGENTCORE_MCP_TOOL_PREFIX)) {
    throw badRequest(
      `AgentCore tool name must start with ${AGENTCORE_MCP_TOOL_PREFIX}.`,
      'invalid_tool_name',
    );
  }
  const toolName = qualifiedToolName.slice(AGENTCORE_MCP_TOOL_PREFIX.length);
  if (!isMcpToolName(toolName)) {
    throw badRequest(`Unknown AgentCore tool: ${toolName}`, 'unknown_tool');
  }
  return {
    messageVersion,
    awsRequestId: requiredMetadata(
      custom,
      'bedrockAgentCoreAwsRequestId',
    ),
    mcpMessageId: requiredMetadata(
      custom,
      'bedrockAgentCoreMcpMessageId',
    ),
    gatewayId,
    targetId,
    toolName,
  };
}

async function dispatch(
  services: HostedMcpServices,
  toolName: McpToolName,
  event: unknown,
): Promise<unknown> {
  switch (toolName) {
    case 'list_applications': {
      const input = ListApplicationsToolInputSchema.parse(event);
      return services.listApplications(input.owner_id);
    }
    case 'get_application': {
      const input = GetApplicationToolInputSchema.parse(event);
      return services.getApplication(input.owner_id, input.application_id);
    }
    case 'create_application': {
      const {
        owner_id,
        idempotency_key,
        ...application
      } = CreateApplicationToolInputSchema.parse(event);
      return services.createApplication(
        owner_id,
        idempotency_key,
        application,
      );
    }
    case 'update_application': {
      const {
        owner_id,
        idempotency_key,
        application_id,
        ...application
      } = UpdateApplicationToolInputSchema.parse(event);
      return services.updateApplication(
        owner_id,
        idempotency_key,
        application_id,
        application,
      );
    }
    case 'delete_application': {
      const input = DeleteApplicationToolInputSchema.parse(event);
      return services.deleteApplication(
        input.owner_id,
        input.idempotency_key,
        input.application_id,
      );
    }
    case 'list_runs': {
      const input = ListRunsToolInputSchema.parse(event);
      return services.listRuns(
        input.owner_id,
        input.statuses === undefined
          ? undefined
          : new Set<string>(input.statuses),
      );
    }
    case 'get_run': {
      const input = GetRunToolInputSchema.parse(event);
      return services.getRun(input.owner_id, input.run_id);
    }
    case 'start_run': {
      const {
        owner_id,
        idempotency_key,
        ...run
      } = StartRunToolInputSchema.parse(event);
      return services.startRun(owner_id, idempotency_key, run);
    }
    case 'pause_run': {
      const input = PauseRunToolInputSchema.parse(event);
      return services.pauseRun(
        input.owner_id,
        input.idempotency_key,
        input.run_id,
      );
    }
    case 'stop_run': {
      const input = StopRunToolInputSchema.parse(event);
      return services.stopRun(
        input.owner_id,
        input.idempotency_key,
        input.run_id,
      );
    }
    case 'resume_run': {
      const input = ResumeRunToolInputSchema.parse(event);
      return services.resumeRun(
        input.owner_id,
        input.idempotency_key,
        input.run_id,
      );
    }
    case 'list_pending_interactions': {
      const input = ListPendingInteractionsToolInputSchema.parse(event);
      return services.pendingInteractions(input.owner_id, input.run_id);
    }
    case 'respond_to_interaction': {
      const input = RespondToInteractionToolInputSchema.parse(event);
      return services.respondToInteraction(
        input.owner_id,
        input.idempotency_key,
        input.run_id,
        input.interaction_id,
        input.revision,
        input.text,
      );
    }
    case 'skip_interaction': {
      const input = SkipInteractionToolInputSchema.parse(event);
      return services.skipInteraction(
        input.owner_id,
        input.idempotency_key,
        input.run_id,
        input.interaction_id,
        input.revision,
      );
    }
  }
}

function logRecord(
  level: 'info' | 'warn' | 'error',
  event: string,
  fields: Record<string, unknown>,
): string {
  return JSON.stringify({
    level,
    event,
    service: 'threatforest-agentcore-mcp',
    ...fields,
  });
}

function internalErrorFields(error: unknown): Record<string, unknown> {
  if (!(error instanceof Error)) {
    return { errorType: typeof error };
  }
  return {
    errorName: error.name,
    errorMessage: error.message,
    ...(error.stack === undefined ? {} : { stack: error.stack }),
  };
}

export function createAgentCoreMcpHandler(
  options: AgentCoreMcpHandlerOptions,
): (
  event: unknown,
  context: AgentCoreLambdaContext,
) => Promise<AgentCoreMcpResponse> {
  const logger = options.logger ?? console;
  return async (event, context) => {
    const startedAt = Date.now();
    let metadata: AgentCoreInvocationMetadata | undefined;
    try {
      metadata = invocationMetadata(context, options.environment);
      logger.info(
        logRecord('info', 'mcp_tool_started', {
          tool: metadata.toolName,
          agentCoreRequestId: metadata.awsRequestId,
          mcpMessageId: metadata.mcpMessageId,
          lambdaRequestId: context.awsRequestId,
        }),
      );
      const result = await dispatch(
        options.services,
        metadata.toolName,
        event,
      );
      logger.info(
        logRecord('info', 'mcp_tool_completed', {
          tool: metadata.toolName,
          agentCoreRequestId: metadata.awsRequestId,
          mcpMessageId: metadata.mcpMessageId,
          lambdaRequestId: context.awsRequestId,
          durationMs: Date.now() - startedAt,
        }),
      );
      return { ok: true, tool: metadata.toolName, result };
    } catch (error) {
      const mapped = mapError(error);
      const fields = {
        tool: metadata?.toolName,
        agentCoreRequestId: metadata?.awsRequestId,
        mcpMessageId: metadata?.mcpMessageId,
        lambdaRequestId: context.awsRequestId,
        status: mapped.status,
        code: mapped.code,
        durationMs: Date.now() - startedAt,
      };
      if (mapped.status >= 500) {
        logger.error(
          logRecord('error', 'mcp_tool_failed', {
            ...fields,
            ...internalErrorFields(error),
          }),
        );
      } else {
        logger.warn(logRecord('warn', 'mcp_tool_rejected', fields));
      }
      return {
        ok: false,
        error: {
          status: mapped.status,
          code: mapped.code,
          message: mapped.expose
            ? mapped.message
            : 'Internal server error.',
        },
      };
    }
  };
}

let defaultHandlerPromise:
  | Promise<
      (
        event: unknown,
        context: AgentCoreLambdaContext,
      ) => Promise<AgentCoreMcpResponse>
    >
  | undefined;

async function getDefaultHandler() {
  defaultHandlerPromise ??= (async () => {
    const environment = readHostedMcpLambdaEnvironment();
    return createAgentCoreMcpHandler({
      services: await getHostedMcpComposition(),
      environment,
    });
  })();
  return defaultHandlerPromise;
}

export async function handler(
  event: unknown,
  context: AgentCoreLambdaContext,
): Promise<AgentCoreMcpResponse> {
  try {
    return await (await getDefaultHandler())(event, context);
  } catch (error) {
    console.error(
      logRecord('error', 'mcp_handler_initialization_failed', {
        lambdaRequestId: context.awsRequestId,
        ...internalErrorFields(error),
      }),
    );
    return {
      ok: false,
      error: {
        status: 500,
        code: 'internal_error',
        message: 'Internal server error.',
      },
    };
  }
}
