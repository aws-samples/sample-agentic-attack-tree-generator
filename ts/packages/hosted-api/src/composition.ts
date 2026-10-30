import {
  ApiGatewayManagementApiClient,
} from '@aws-sdk/client-apigatewaymanagementapi';
import { BedrockClient } from '@aws-sdk/client-bedrock';
import { CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { S3Client } from '@aws-sdk/client-s3';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { SQSClient } from '@aws-sdk/client-sqs';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { DynamoControlPlane } from '@threatforest/control-plane';
import { createAwsHostedReportOutputPublisher } from '@threatforest/hosted-runtime';
import {
  ApplicationService,
  VersionService,
} from './application-service.js';
import type {
  EventAdapter,
  NormalizationOrchestrator,
} from './contracts.js';
import { createHttpHandler } from './http.js';
import { IdempotencyExecutor } from './idempotency.js';
import { HostedMcpServices } from './mcp.js';
import { randomIdFactory, systemClock } from './runtime.js';
import { HitlService, RunService } from './run-service.js';
import { SettingsService } from './settings-service.js';
import { UploadService } from './upload-service.js';
import { ReportImportService } from './report-import-service.js';
import { RunObservabilityService } from './run-observability-service.js';
import {
  ReplayTicketService,
  createWebSocketHandler,
} from './websocket.js';
import { BedrockDiscoveryService } from './aws/discovery.js';
import { S3MultipartStorageAdapter } from './aws/multipart.js';
import { AwsNormalizationOrchestrator } from './aws/ingestion.js';
import { StreamRunOrchestrator } from './aws/orchestrator.js';
import { SecretsManagerStringProvider } from './aws/secrets.js';
import { SecretsManagerProviderCredentialStore } from './aws/provider-credentials.js';
import {
  DynamoApplicationMetadataStore,
  DynamoArtifactResolver,
  DynamoConnectionAdapter,
  DynamoHostedState,
  DynamoMutationResponseStore,
  DynamoRunIndex,
  DynamoUploadSessionStore,
  DynamoVersionStore,
} from './aws/state.js';
import {
  DynamoReportImportStore,
  StreamReportImportDispatcher,
} from './aws/report-imports.js';

export interface HostedApiEnvironment {
  region: string;
  controlPlaneTableName: string;
  artifactsBucket: string;
  artifactsKmsKeyId: string;
  runQueueUrl: string;
  ingestionQueueUrl: string;
  reportImportQueueUrl: string;
  originSecretArn: string;
  replayTicketSecretArn: string;
  providerSecretPrefix: string;
  providerSecretsKmsKeyId: string;
  webSocketManagementEndpoint: string;
  cognitoIssuer?: string;
  cognitoAudience?: string;
  uploadMaximumBytes?: number;
  uploadPartSizeBytes?: number;
  allowUnticketedWebSocket: boolean;
  spansLogGroupName: string;
}

export interface HostedComposition {
  http: ReturnType<typeof createHttpHandler>;
  websocket: ReturnType<typeof createWebSocketHandler>;
  mcp: HostedMcpServices;
}

export interface HostedMcpEnvironment {
  region: string;
  controlPlaneTableName: string;
  ingestionQueueUrl: string;
}

export interface HostedMcpLambdaEnvironment {
  gatewayId: string;
  targetId?: string;
}

export interface HostedWebSocketEnvironment {
  region: string;
  controlPlaneTableName: string;
  originSecretArn: string;
  replayTicketSecretArn: string;
  webSocketManagementEndpoint: string;
  cognitoIssuer?: string;
  cognitoAudience?: string;
  allowUnticketedWebSocket: boolean;
}

export interface HostedWebSocketComposition {
  websocket: ReturnType<typeof createWebSocketHandler>;
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(`${name} environment variable is required`);
  }
  return value;
}

function positiveNumber(
  environment: NodeJS.ProcessEnv,
  name: string,
): number | undefined {
  const raw = environment[name];
  if (raw === undefined || raw === '') {
    return undefined;
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

export function readHostedApiEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): HostedApiEnvironment {
  return {
    region: environment.AWS_REGION ?? 'eu-west-2',
    controlPlaneTableName: required(environment, 'CONTROL_PLANE_TABLE_NAME'),
    artifactsBucket: required(environment, 'ARTIFACTS_BUCKET_NAME'),
    artifactsKmsKeyId: required(environment, 'ARTIFACTS_KMS_KEY_ID'),
    runQueueUrl: required(environment, 'RUN_QUEUE_URL'),
    ingestionQueueUrl: required(environment, 'INGESTION_QUEUE_URL'),
    reportImportQueueUrl: required(environment, 'REPORT_IMPORT_QUEUE_URL'),
    originSecretArn: required(environment, 'ORIGIN_SECRET_ARN'),
    replayTicketSecretArn: required(environment, 'REPLAY_TICKET_SECRET_ARN'),
    providerSecretPrefix: required(
      environment,
      'THREATFOREST_MODEL_SECRET_PREFIX',
    ),
    providerSecretsKmsKeyId: required(
      environment,
      'MODEL_SECRETS_KMS_KEY_ID',
    ),
    webSocketManagementEndpoint: required(
      environment,
      'WEBSOCKET_MANAGEMENT_ENDPOINT',
    ),
    ...(environment.COGNITO_ISSUER === undefined
      ? {}
      : { cognitoIssuer: environment.COGNITO_ISSUER }),
    ...(environment.COGNITO_AUDIENCE === undefined
      ? {}
      : { cognitoAudience: environment.COGNITO_AUDIENCE }),
    ...(positiveNumber(environment, 'UPLOAD_MAXIMUM_BYTES') === undefined
      ? {}
      : {
          uploadMaximumBytes: positiveNumber(
            environment,
            'UPLOAD_MAXIMUM_BYTES',
          ),
        }),
    ...(positiveNumber(environment, 'UPLOAD_PART_SIZE_BYTES') === undefined
      ? {}
      : {
          uploadPartSizeBytes: positiveNumber(
            environment,
            'UPLOAD_PART_SIZE_BYTES',
          ),
        }),
    allowUnticketedWebSocket:
      environment.ALLOW_UNTICKETED_WEBSOCKET === 'true',
    spansLogGroupName: environment.AGENTCORE_SPANS_LOG_GROUP ?? 'aws/spans',
  };
}

export function readHostedMcpEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): HostedMcpEnvironment {
  return {
    region: environment.AWS_REGION ?? 'eu-west-2',
    controlPlaneTableName: required(
      environment,
      'CONTROL_PLANE_TABLE_NAME',
    ),
    ingestionQueueUrl: required(environment, 'INGESTION_QUEUE_URL'),
  };
}

export function readHostedMcpLambdaEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): HostedMcpLambdaEnvironment {
  const targetId = environment.AGENTCORE_TARGET_ID?.trim();
  return {
    gatewayId: required(environment, 'AGENTCORE_GATEWAY_ID'),
    ...(targetId === undefined || targetId === ''
      ? {}
      : { targetId }),
  };
}

export function readHostedWebSocketEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): HostedWebSocketEnvironment {
  return {
    region: environment.AWS_REGION ?? 'eu-west-2',
    controlPlaneTableName: required(
      environment,
      'CONTROL_PLANE_TABLE_NAME',
    ),
    originSecretArn: required(environment, 'ORIGIN_SECRET_ARN'),
    replayTicketSecretArn: required(
      environment,
      'REPLAY_TICKET_SECRET_ARN',
    ),
    webSocketManagementEndpoint: required(
      environment,
      'WEBSOCKET_MANAGEMENT_ENDPOINT',
    ),
    ...(environment.COGNITO_ISSUER === undefined
      ? {}
      : { cognitoIssuer: environment.COGNITO_ISSUER }),
    ...(environment.COGNITO_AUDIENCE === undefined
      ? {}
      : { cognitoAudience: environment.COGNITO_AUDIENCE }),
    allowUnticketedWebSocket:
      environment.ALLOW_UNTICKETED_WEBSOCKET === 'true',
  };
}

interface HostedDynamoCore {
  controlPlane: DynamoControlPlane;
  hostedState: DynamoHostedState;
  applications: ApplicationService;
  runs: RunService;
  hitl: HitlService;
}

function createDocumentClient(region: string): DynamoDBDocumentClient {
  return DynamoDBDocumentClient.from(new DynamoDBClient({ region }), {
    marshallOptions: { removeUndefinedValues: true },
  });
}

function composeHostedDynamoCore(options: {
  tableName: string;
  documentClient: DynamoDBDocumentClient;
  normalization?: NormalizationOrchestrator;
  webSocketManagementClient?: ApiGatewayManagementApiClient;
}): HostedDynamoCore {
  const controlPlane = new DynamoControlPlane({
    tableName: options.tableName,
    client: options.documentClient,
  });
  const hostedState = new DynamoHostedState({
    tableName: options.tableName,
    documentClient: options.documentClient,
    ...(options.webSocketManagementClient === undefined
      ? {}
      : {
          webSocketManagementClient:
            options.webSocketManagementClient,
        }),
  });
  const metadata = new DynamoApplicationMetadataStore(hostedState);
  const versions = new DynamoVersionStore(hostedState);
  const runIndex = new DynamoRunIndex(hostedState);
  const responses = new DynamoMutationResponseStore(hostedState);
  const idempotency = new IdempotencyExecutor({
    store: controlPlane,
    responses,
    clock: systemClock,
  });
  const applications = new ApplicationService({
    controlPlane,
    metadata,
    versions,
    idempotency,
    ids: randomIdFactory,
    clock: systemClock,
  });
  const settings = new SettingsService({
    controlPlane,
    applications,
    idempotency,
    clock: systemClock,
  });
  const orchestrator = new StreamRunOrchestrator();
  const runs = new RunService({
    controlPlane,
    applications,
    settings,
    runIndex,
    orchestrator,
    artifacts: new DynamoArtifactResolver(
      hostedState,
      options.normalization,
    ),
    idempotency,
    ids: randomIdFactory,
    clock: systemClock,
  });
  const hitl = new HitlService({
    controlPlane,
    runs,
    orchestrator,
    idempotency,
    clock: systemClock,
  });
  return { controlPlane, hostedState, applications, runs, hitl };
}

export async function composeHostedMcp(
  config: HostedMcpEnvironment = readHostedMcpEnvironment(),
): Promise<HostedMcpServices> {
  const documentClient = createDocumentClient(config.region);
  const normalization = new AwsNormalizationOrchestrator({
    tableName: config.controlPlaneTableName,
    queueUrl: config.ingestionQueueUrl,
    documentClient,
    sqsClient: new SQSClient({ region: config.region }),
    dispatchViaStream: true,
  });
  const core = composeHostedDynamoCore({
    tableName: config.controlPlaneTableName,
    documentClient,
    normalization,
  });
  return new HostedMcpServices({
    applications: core.applications,
    runs: core.runs,
    hitl: core.hitl,
  });
}

export async function composeHostedWebSocket(
  config: HostedWebSocketEnvironment = readHostedWebSocketEnvironment(),
): Promise<HostedWebSocketComposition> {
  const dynamo = createDocumentClient(config.region);
  const webSocketManagement = new ApiGatewayManagementApiClient({
    region: config.region,
    endpoint: config.webSocketManagementEndpoint,
  });
  const core = composeHostedDynamoCore({
    tableName: config.controlPlaneTableName,
    documentClient: dynamo,
    webSocketManagementClient: webSocketManagement,
  });
  const secretsClient = new SecretsManagerClient({ region: config.region });
  const [originVerificationSecret, replayTicketSecret] = await Promise.all([
    new SecretsManagerStringProvider(
      secretsClient,
      config.originSecretArn,
      16,
    ).load(),
    new SecretsManagerStringProvider(
      secretsClient,
      config.replayTicketSecretArn,
      32,
    ).load(),
  ]);
  const tickets = new ReplayTicketService({
    secret: replayTicketSecret,
    runs: core.runs,
    ids: randomIdFactory,
    clock: systemClock,
  });
  const cognito = {
    ...(config.cognitoIssuer === undefined
      ? {}
      : { issuer: config.cognitoIssuer }),
    ...(config.cognitoAudience === undefined
      ? {}
      : { audience: config.cognitoAudience }),
  };
  return {
    websocket: createWebSocketHandler({
      originSecret: originVerificationSecret,
      tickets,
      connections: new DynamoConnectionAdapter(core.hostedState),
      events: {
        list: (scope, runId, afterSequence) =>
          core.controlPlane.listEvents(scope, runId, afterSequence),
      },
      clock: systemClock,
      cognito,
      allowUnticketedConnections: config.allowUnticketedWebSocket,
      runs: core.runs,
    }),
  };
}

export async function composeHostedApi(
  config: HostedApiEnvironment = readHostedApiEnvironment(),
): Promise<HostedComposition> {
  const documentClient = createDocumentClient(config.region);
  const s3 = new S3Client({ region: config.region });
  const webSocketManagement = new ApiGatewayManagementApiClient({
    region: config.region,
    endpoint: config.webSocketManagementEndpoint,
  });
  const secretsClient = new SecretsManagerClient({ region: config.region });
  const [originVerificationSecret, replayTicketSecret] = await Promise.all([
    new SecretsManagerStringProvider(
      secretsClient,
      config.originSecretArn,
      16,
    ).load(),
    new SecretsManagerStringProvider(
      secretsClient,
      config.replayTicketSecretArn,
      32,
    ).load(),
  ]);
  const controlPlane = new DynamoControlPlane({
    tableName: config.controlPlaneTableName,
    client: documentClient,
  });
  const hostedState = new DynamoHostedState({
    tableName: config.controlPlaneTableName,
    documentClient,
    s3,
    artifactsBucket: config.artifactsBucket,
    webSocketManagementClient: webSocketManagement,
    prepareApplicationReport: async scope => {
      const publisher = await createAwsHostedReportOutputPublisher({
        tableName: config.controlPlaneTableName,
        bucketName: config.artifactsBucket,
        kmsKeyId: config.artifactsKmsKeyId,
        region: config.region,
      });
      await publisher.ensureApplicationReport(scope);
    },
  });
  const metadata = new DynamoApplicationMetadataStore(hostedState);
  const versionsStore = new DynamoVersionStore(hostedState);
  const runIndex = new DynamoRunIndex(hostedState);
  const responses = new DynamoMutationResponseStore(hostedState);
  const uploadSessions = new DynamoUploadSessionStore(hostedState);
  const connections = new DynamoConnectionAdapter(hostedState);
  const normalization = new AwsNormalizationOrchestrator({
    tableName: config.controlPlaneTableName,
    queueUrl: config.ingestionQueueUrl,
    documentClient,
    sqsClient: new SQSClient({ region: config.region }),
    dispatchViaStream: true,
  });
  const artifacts = new DynamoArtifactResolver(hostedState, normalization);
  const idempotency = new IdempotencyExecutor({
    store: controlPlane,
    responses,
    clock: systemClock,
  });
  const applications = new ApplicationService({
    controlPlane,
    metadata,
    versions: versionsStore,
    idempotency,
    ids: randomIdFactory,
    clock: systemClock,
  });
  const settings = new SettingsService({
    controlPlane,
    applications,
    discovery: new BedrockDiscoveryService(
      new BedrockClient({ region: config.region }),
      config.region,
      (region) => new BedrockClient({ region }),
    ),
    credentials: new SecretsManagerProviderCredentialStore({
      client: secretsClient,
      secretPrefix: config.providerSecretPrefix,
      kmsKeyId: config.providerSecretsKmsKeyId,
    }),
    idempotency,
    clock: systemClock,
    defaults: { awsRegion: config.region },
  });
  const runOrchestrator = new StreamRunOrchestrator();
  const runs = new RunService({
    controlPlane,
    applications,
    settings,
    runIndex,
    orchestrator: runOrchestrator,
    artifacts,
    idempotency,
    ids: randomIdFactory,
    clock: systemClock,
  });
  const hitl = new HitlService({
    controlPlane,
    runs,
    orchestrator: runOrchestrator,
    idempotency,
    clock: systemClock,
  });
  const observability = new RunObservabilityService({
    runs,
    region: config.region,
    logGroupName: config.spansLogGroupName,
    client: new CloudWatchLogsClient({ region: config.region }),
  });
  const versions = new VersionService({
    applications,
    versions: versionsStore,
    idempotency,
    clock: systemClock,
  });
  const uploads = new UploadService({
    applications,
    sessions: uploadSessions,
    storage: new S3MultipartStorageAdapter(s3),
    normalization,
    idempotency,
    ids: randomIdFactory,
    clock: systemClock,
    bucket: config.artifactsBucket,
    kmsKeyId: config.artifactsKmsKeyId,
    ...(config.uploadMaximumBytes === undefined
      ? {}
      : { maximumSizeBytes: config.uploadMaximumBytes }),
    ...(config.uploadPartSizeBytes === undefined
      ? {}
      : { defaultPartSizeBytes: config.uploadPartSizeBytes }),
  });
  const imports = new ReportImportService({
    store: new DynamoReportImportStore(
      config.controlPlaneTableName,
      documentClient,
    ),
    storage: new S3MultipartStorageAdapter(s3),
    dispatcher: new StreamReportImportDispatcher(),
    idempotency,
    ids: randomIdFactory,
    clock: systemClock,
    bucket: config.artifactsBucket,
    kmsKeyId: config.artifactsKmsKeyId,
    maximumSizeBytes: 200 * 1024 * 1024,
  });
  const tickets = new ReplayTicketService({
    secret: replayTicketSecret,
    runs,
    ids: randomIdFactory,
    clock: systemClock,
  });
  const cognito = {
    ...(config.cognitoIssuer === undefined
      ? {}
      : { issuer: config.cognitoIssuer }),
    ...(config.cognitoAudience === undefined
      ? {}
      : { audience: config.cognitoAudience }),
  };
  const services = {
    applications,
    versions,
    settings,
    runs,
    observability,
    hitl,
    uploads,
    imports,
    tickets,
  };
  const events: EventAdapter = {
    list: (scope, runId, afterSequence) =>
      controlPlane.listEvents(scope, runId, afterSequence),
  };
  return {
    http: createHttpHandler({
      originSecret: originVerificationSecret,
      services,
      cognito,
    }),
    websocket: createWebSocketHandler({
      originSecret: originVerificationSecret,
      tickets,
      connections,
      events,
      clock: systemClock,
      cognito,
      allowUnticketedConnections: config.allowUnticketedWebSocket,
      runs,
    }),
    mcp: new HostedMcpServices({ applications, runs, hitl }),
  };
}

let compositionPromise: Promise<HostedComposition> | undefined;
let mcpCompositionPromise: Promise<HostedMcpServices> | undefined;
let webSocketCompositionPromise:
  | Promise<HostedWebSocketComposition>
  | undefined;

export function getHostedComposition(): Promise<HostedComposition> {
  compositionPromise ??= composeHostedApi();
  return compositionPromise;
}

export function getHostedMcpComposition(): Promise<HostedMcpServices> {
  mcpCompositionPromise ??= composeHostedMcp();
  return mcpCompositionPromise;
}

export function getHostedWebSocketComposition(): Promise<HostedWebSocketComposition> {
  webSocketCompositionPromise ??= composeHostedWebSocket();
  return webSocketCompositionPromise;
}
