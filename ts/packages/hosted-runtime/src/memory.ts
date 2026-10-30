import type {
  ApplicationId,
  HitlRequest,
  HitlResponse,
  RunId,
} from '@threatforest/types';
import { canonicalJson, sha256 } from './util.js';

export interface ApprovedFeedbackMemoryInput {
  actorId: string;
  applicationId: ApplicationId;
  runId: RunId;
  request: HitlRequest;
  response: HitlResponse;
}

export interface ThreatModelMemoryInput {
  actorId: string;
  applicationId: ApplicationId;
  runId: RunId;
  createdAt: string;
  threatModel: Readonly<Record<string, unknown>>;
}

export interface ApplicationMemoryContextInput {
  actorId: string;
  applicationId: ApplicationId;
  query: string;
  topK?: number;
}

export interface ApprovedFeedbackMemory {
  recordApprovedFeedback(input: ApprovedFeedbackMemoryInput): Promise<void>;
  recordThreatModel(input: ThreatModelMemoryInput): Promise<void>;
  retrieveApplicationContext(
    input: ApplicationMemoryContextInput,
  ): Promise<readonly string[]>;
}

interface AgentCoreMemoryApi {
  createEvent(input: {
    memoryId: string;
    actorId: string;
    sessionId: string;
    eventTimestamp: Date;
    payload: Array<{
      conversational: {
        content: { text: string };
        role: 'USER' | 'ASSISTANT';
      };
    }>;
    clientToken: string;
    metadata: Record<string, { stringValue: string }>;
  }): Promise<void>;
  retrieveMemoryRecords?(input: {
    memoryId: string;
    namespace: string;
    searchCriteria: {
      searchQuery: string;
      topK: number;
    };
    maxResults: number;
  }): Promise<
    readonly {
      content?: { text?: string };
      score?: number;
    }[]
  >;
}

export interface AgentCoreApprovedFeedbackMemoryOptions {
  memoryId: string;
  client: AgentCoreMemoryApi;
}

export class AgentCoreApprovedFeedbackMemory implements ApprovedFeedbackMemory {
  readonly #memoryId: string;
  readonly #client: AgentCoreMemoryApi;

  constructor(options: AgentCoreApprovedFeedbackMemoryOptions) {
    this.#memoryId = options.memoryId;
    this.#client = options.client;
  }

  async recordApprovedFeedback(input: ApprovedFeedbackMemoryInput): Promise<void> {
    const content = canonicalJson({
      type: 'threatforest_approved_feedback',
      application_id: input.applicationId,
      run_id: input.runId,
      stage_id: input.request.stage_id,
      interaction_kind: input.request.kind,
      revision: input.response.revision,
      action: input.response.action,
      response: input.response.text,
    });
    await this.#client.createEvent({
      memoryId: this.#memoryId,
      actorId: input.actorId,
      sessionId: input.runId,
      eventTimestamp: new Date(input.response.submitted_at),
      payload: [
        {
          conversational: {
            content: { text: content.slice(0, 100_000) },
            role: 'USER',
          },
        },
      ],
      clientToken: sha256(
        `${input.actorId}\0${input.runId}\0${input.request.interaction_id}\0${input.response.revision}`,
      ),
      metadata: {
        application_id: { stringValue: input.applicationId },
        run_id: { stringValue: input.runId },
        stage_id: { stringValue: input.request.stage_id },
        interaction_kind: { stringValue: input.request.kind },
        action: { stringValue: input.response.action },
      },
    });
  }

  async recordThreatModel(input: ThreatModelMemoryInput): Promise<void> {
    const content = compactThreatModel(input);
    await this.#client.createEvent({
      memoryId: this.#memoryId,
      actorId: input.actorId,
      sessionId: input.runId,
      eventTimestamp: new Date(input.createdAt),
      payload: [
        {
          conversational: {
            content: { text: content },
            role: 'ASSISTANT',
          },
        },
      ],
      clientToken: sha256(
        `${input.actorId}\0${input.runId}\0threat-model-summary\0v1`,
      ),
      metadata: {
        application_id: { stringValue: input.applicationId },
        run_id: { stringValue: input.runId },
        record_type: { stringValue: 'threat_model' },
      },
    });
  }

  async retrieveApplicationContext(
    input: ApplicationMemoryContextInput,
  ): Promise<readonly string[]> {
    if (this.#client.retrieveMemoryRecords === undefined) {
      return [];
    }
    const topK = Math.max(1, Math.min(20, Math.trunc(input.topK ?? 5)));
    const namespaces = [
      `/threatforest/${input.actorId}/summaries`,
      `/threatforest/${input.actorId}/approved-feedback`,
    ];
    const responses = await Promise.all(
      namespaces.map((namespace) =>
        this.#client.retrieveMemoryRecords!({
          memoryId: this.#memoryId,
          namespace,
          searchCriteria: {
            searchQuery: input.query.slice(0, 10_000),
            topK,
          },
          maxResults: topK,
        }),
      ),
    );
    const context: string[] = [];
    const seen = new Set<string>();
    let totalBytes = 0;
    for (const record of responses.flat()) {
      const text = record.content?.text?.trim();
      if (!text || seen.has(text)) {
        continue;
      }
      const bytes = Buffer.byteLength(text);
      if (totalBytes + bytes > 100_000) {
        break;
      }
      seen.add(text);
      context.push(text);
      totalBytes += bytes;
    }
    return context;
  }
}

interface AwsCommandClient {
  send(command: unknown): Promise<Record<string, unknown>>;
}

interface AgentCoreSdkModule {
  BedrockAgentCoreClient: new (
    configuration: Record<string, unknown>,
  ) => AwsCommandClient;
  CreateEventCommand: new (input: Record<string, unknown>) => unknown;
  RetrieveMemoryRecordsCommand: new (
    input: Record<string, unknown>,
  ) => unknown;
}

export interface AwsAgentCoreMemoryFactoryOptions {
  memoryId: string;
  region?: string;
  clientConfig?: Record<string, unknown>;
}

export async function createAwsAgentCoreApprovedFeedbackMemory(
  options: AwsAgentCoreMemoryFactoryOptions,
): Promise<ApprovedFeedbackMemory> {
  const packageName: string = '@aws-sdk/client-bedrock-agentcore';
  const module = (await import(packageName)) as unknown as AgentCoreSdkModule;
  const client = new module.BedrockAgentCoreClient({
    ...(options.region === undefined ? {} : { region: options.region }),
    ...options.clientConfig,
  });
  return new AgentCoreApprovedFeedbackMemory({
    memoryId: options.memoryId,
    client: {
      async createEvent(input): Promise<void> {
        await client.send(new module.CreateEventCommand(input));
      },
      async retrieveMemoryRecords(input) {
        const response = await client.send(
          new module.RetrieveMemoryRecordsCommand(input),
        );
        return Array.isArray(response['memoryRecordSummaries'])
          ? (response['memoryRecordSummaries'] as Array<{
              content?: { text?: string };
              score?: number;
            }>)
          : [];
      },
    },
  });
}

function compactThreatModel(input: ThreatModelMemoryInput): string {
  const compact = {
    type: 'threatforest_threat_model',
    application_id: input.applicationId,
    run_id: input.runId,
    created_at: input.createdAt,
    threat_model: compactValue(input.threatModel, 0, 100),
  };
  let serialized = canonicalJson(compact);
  if (Buffer.byteLength(serialized) <= 100_000) {
    return serialized;
  }
  serialized = canonicalJson({
    ...compact,
    threat_model: compactValue(input.threatModel, 0, 20),
  });
  if (Buffer.byteLength(serialized) <= 100_000) {
    return serialized;
  }
  return canonicalJson({
    type: 'threatforest_threat_model',
    application_id: input.applicationId,
    run_id: input.runId,
    created_at: input.createdAt,
    threat_model_sha256: sha256(canonicalJson(input.threatModel)),
    extraction_summary: compactValue(
      input.threatModel['extraction_summary'],
      0,
      10,
    ),
    mapping_summary: compactValue(
      input.threatModel['mapping_summary'],
      0,
      10,
    ),
    note: 'The complete threat model is retained in encrypted S3.',
  });
}

function compactValue(
  value: unknown,
  depth: number,
  maxArrayItems: number,
): unknown {
  if (depth >= 8) {
    return '[depth limit]';
  }
  if (typeof value === 'string') {
    return value.length <= 4_000 ? value : `${value.slice(0, 4_000)}...`;
  }
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'number'
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, maxArrayItems)
      .map((entry) => compactValue(entry, depth + 1, maxArrayItems));
  }
  if (typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .slice(0, 200)
        .map(([key, entry]) => [
          key,
          compactValue(entry, depth + 1, maxArrayItems),
        ]),
    );
  }
  return String(value);
}
