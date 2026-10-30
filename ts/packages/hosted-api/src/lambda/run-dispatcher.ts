import {
  BedrockAgentCoreClient,
  InvokeAgentRuntimeCommand,
} from '@aws-sdk/client-bedrock-agentcore';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import {
  ApplicationIdSchema,
  RunIdSchema,
  UserIdSchema,
  type ApplicationId,
  type RunId,
  type UserId,
} from '@threatforest/types';
import {
  DynamoControlPlane,
  type ControlPlaneScope,
  type RunRecord,
} from '@threatforest/control-plane';

interface RunCommand {
  schema_version: 1;
  command: 'execute' | 'pause' | 'stop';
  owner_id: UserId;
  application_id: ApplicationId;
  run_id: RunId;
  trace_id?: string;
}

interface RuntimeBoundary {
  boundary?: string;
  error?: string;
  message?: string;
}

const DURABLE_BOUNDARIES = new Set([
  'completed',
  'awaiting_input',
  'failed',
  'busy',
]);

export class RuntimeClientError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'RuntimeClientError';
  }
}

interface RuntimeInvocationPayload {
  operation: 'execute_run' | 'control_run';
  application_id: ApplicationId;
  run_id: RunId;
  dispatch_generation?: number;
  action?: 'pause' | 'stop';
}

export const RUNTIME_PRINCIPAL_HEADER =
  'X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserId';

let client: BedrockAgentCoreClient | undefined;
let controlPlane: DynamoControlPlane | undefined;

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} environment variable is required`);
  }
  return value;
}

function commandBody(event: unknown): unknown {
  if (typeof event !== 'object' || event === null || Array.isArray(event)) {
    return event;
  }
  const body = (event as Record<string, unknown>).body;
  if (body === undefined) {
    return event;
  }
  if (typeof body !== 'string') {
    return body;
  }
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new Error('Run command body is not valid JSON');
  }
}

export function runCommand(event: unknown): RunCommand {
  const value = commandBody(event);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Run command must be an object');
  }
  const item = value as Partial<RunCommand>;
  if (
    item.schema_version !== 1 ||
    !['execute', 'pause', 'stop'].includes(item.command ?? '') ||
    typeof item.owner_id !== 'string' ||
    typeof item.application_id !== 'string' ||
    typeof item.run_id !== 'string'
  ) {
    throw new Error('Run command is malformed');
  }
  return {
    schema_version: 1,
    command: item.command as RunCommand['command'],
    owner_id: UserIdSchema.parse(item.owner_id),
    application_id: ApplicationIdSchema.parse(item.application_id),
    run_id: RunIdSchema.parse(item.run_id),
    ...(typeof item.trace_id === 'string'
      ? { trace_id: item.trace_id }
      : {}),
  };
}

interface RunLookup {
  getRun(scope: ControlPlaneScope, runId: RunId): Promise<RunRecord | null>;
}

export async function authorizeRunCommand(
  event: unknown,
  runs: RunLookup,
): Promise<{ input: RunCommand; run: RunRecord }> {
  const input = runCommand(event);
  const run = await runs.getRun(
    {
      owner_id: input.owner_id,
      application_id: input.application_id,
    },
    input.run_id,
  );
  if (
    run === null ||
    run.owner_id !== input.owner_id ||
    run.application_id !== input.application_id ||
    run.run_id !== input.run_id
  ) {
    throw new Error('Run command does not match a canonical run');
  }
  return { input, run };
}

export function runtimeInvocationPayload(
  input: RunCommand,
  run: RunRecord,
): RuntimeInvocationPayload {
  if (input.command === 'execute') {
    return {
      operation: 'execute_run',
      application_id: run.application_id,
      run_id: run.run_id,
      dispatch_generation: run.revision,
    };
  }
  return {
    operation: 'control_run',
    application_id: run.application_id,
    run_id: run.run_id,
    action: input.command,
  };
}

export function addRuntimePrincipalHeader(
  headers: Record<string, string>,
  ownerId: UserId,
): void {
  headers[RUNTIME_PRINCIPAL_HEADER] = ownerId;
}

function runtimeInvocationCommand(
  runtimeArn: string,
  qualifier: string,
  payload: RuntimeInvocationPayload,
  run: RunRecord,
): InvokeAgentRuntimeCommand {
  const command = new InvokeAgentRuntimeCommand({
    agentRuntimeArn: runtimeArn,
    qualifier,
    runtimeSessionId: run.run_id,
    runtimeUserId: run.owner_id,
    traceId: run.trace_id,
    contentType: 'application/json',
    accept: 'application/json',
    payload: Buffer.from(JSON.stringify(payload)),
  });
  command.middlewareStack.add(
    (next) => async (arguments_) => {
      const request = arguments_.request as {
        headers?: Record<string, string>;
      };
      if (request.headers === undefined) {
        throw new Error('AgentCore invocation request has no headers');
      }
      addRuntimePrincipalHeader(request.headers, run.owner_id);
      return next(arguments_);
    },
    {
      name: 'threatForestRuntimePrincipalHeader',
      step: 'build',
      priority: 'high',
    },
  );
  return command;
}

async function responseText(value: unknown): Promise<string> {
  if (
    typeof value === 'object' &&
    value !== null &&
    'transformToString' in value &&
    typeof (value as { transformToString?: unknown }).transformToString ===
      'function'
  ) {
    return (value as { transformToString(): Promise<string> }).transformToString();
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString('utf8');
  }
  return '';
}

export function parseRuntimeBoundary(text: string): RuntimeBoundary {
  if (text.trim() === '') {
    throw new RuntimeClientError(
      'AgentCore Runtime returned an empty response; retry the durable command',
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    throw new RuntimeClientError(
      'AgentCore Runtime response is not valid JSON',
      error,
    );
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new RuntimeClientError(
      'AgentCore Runtime response must be a JSON object',
    );
  }
  const value = parsed as Record<string, unknown>;
  const boundary =
    typeof value['boundary'] === 'string' ? value['boundary'] : undefined;
  const runtimeError =
    typeof value['error'] === 'string' && value['error'].trim() !== ''
      ? value['error']
      : undefined;
  if (runtimeError === undefined && !DURABLE_BOUNDARIES.has(boundary ?? '')) {
    throw new RuntimeClientError(
      'AgentCore Runtime returned no valid durable boundary; retry the durable command',
    );
  }
  return {
    ...(boundary === undefined ? {} : { boundary }),
    ...(runtimeError === undefined ? {} : { error: runtimeError }),
    ...(typeof value['message'] === 'string'
      ? { message: value['message'] }
      : {}),
  };
}

export async function handler(event: unknown): Promise<RuntimeBoundary> {
  const { input, run } = await authorizeRunCommand(
    event,
    getControlPlane(),
  );
  const runtimeArn = required('AGENTCORE_RUNTIME_ARN');
  const qualifier = process.env.AGENTCORE_RUNTIME_QUALIFIER?.trim() || 'DEFAULT';
  client ??= new BedrockAgentCoreClient({
    region: process.env.AWS_REGION || 'eu-west-2',
  });
  const payload = runtimeInvocationPayload(input, run);
  let runtimeSessionId: string | undefined;
  let result: RuntimeBoundary;
  try {
    const response = await client.send(
      runtimeInvocationCommand(runtimeArn, qualifier, payload, run),
    );
    runtimeSessionId = response.runtimeSessionId;
    result = parseRuntimeBoundary(await responseText(response.response));
  } catch (error) {
    if (error instanceof RuntimeClientError) throw error;
    throw new RuntimeClientError('AgentCore Runtime invocation failed', error);
  }
  if (result.error) {
    throw new Error(`AgentCore Runtime failed: ${result.error}`);
  }
  console.info(
    JSON.stringify({
      event: result.boundary === 'busy'
        ? 'threatforest.run_command.pending'
        : 'threatforest.run_command.completed',
      command: input.command,
      runId: input.run_id,
      boundary: result.boundary ?? 'unknown',
      runtimeSessionId,
    }),
  );
  return result;
}

export function resetClientForTest(): void {
  client = undefined;
  controlPlane = undefined;
}

function getControlPlane(): DynamoControlPlane {
  controlPlane ??= new DynamoControlPlane({
    tableName: required('CONTROL_PLANE_TABLE_NAME'),
    client: DynamoDBDocumentClient.from(
      new DynamoDBClient({
        region: process.env.AWS_REGION || 'eu-west-2',
      }),
      { marshallOptions: { removeUndefinedValues: true } },
    ),
  });
  return controlPlane;
}
