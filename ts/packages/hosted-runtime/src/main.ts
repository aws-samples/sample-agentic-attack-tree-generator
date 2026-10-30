import { createDynamoControlPlaneStore, createS3TranscriptArtifactStore, AwsKmsGenerateMacClient } from './aws-adapters.js';
import { DurableBoundaryExecutor } from './executor.js';
import { EngineGraphStageExecutor } from './engine-adapter.js';
import {
  AgentCoreRuntimeUserPrincipalResolver,
  CognitoJwtPrincipalResolver,
  KmsHmacActorIdDeriver,
} from './identity.js';
import { createAwsAgentCoreApprovedFeedbackMemory } from './memory.js';
import { SecretsManagerModelCredentialResolver } from './model-credentials.js';
import { createAgentCoreNodeServer, listen } from './node-server.js';
import { createAwsHostedReportOutputPublisher } from './output-publisher.js';
import {
  installGracefulShutdown,
  loadProductionConfig,
  type ProductionConfig,
} from './production.js';
import { AgentCoreHttpRuntime } from './runtime.js';
import { createAwsS3IngestionWorkspaceResolver } from './s3-ingestion-workspace.js';
import { createAgentCoreHostedTelemetry } from './telemetry.js';

export async function composeProductionServer(config: ProductionConfig): Promise<{
  server: ReturnType<typeof createAgentCoreNodeServer>;
  abortController: AbortController;
}> {
  const [
    store,
    artifactStore,
    macClient,
    memory,
    workspaceResolver,
  ] =
    await Promise.all([
      createDynamoControlPlaneStore({
        tableName: config.stateTableName,
        applicationIndexName: config.stateTableApplicationIndexName,
        region: config.region,
      }),
      createS3TranscriptArtifactStore({
        bucketName: config.artifactBucketName,
        kmsKeyId: config.artifactKmsKeyId,
        keyPrefix: config.artifactKeyPrefix,
        region: config.region,
      }),
      AwsKmsGenerateMacClient.create({ region: config.region }),
      createAwsAgentCoreApprovedFeedbackMemory({
        memoryId: config.memoryId,
        region: config.region,
      }),
      createAwsS3IngestionWorkspaceResolver({
        tableName: config.stateTableName,
        bucketName: config.artifactBucketName,
        kmsKeyId: config.artifactKmsKeyId,
        keyPrefix: config.artifactKeyPrefix,
        workspaceRoot: config.workspaceRoot,
        region: config.region,
      }),
    ]);
  const outputPublisher = await createAwsHostedReportOutputPublisher({
    tableName: config.stateTableName,
    bucketName: config.artifactBucketName,
    kmsKeyId: config.artifactKmsKeyId,
    keyPrefix: config.artifactKeyPrefix,
    region: config.region,
    memory,
  });
  const principalResolver =
    config.principalMode === 'runtime_user_id'
      ? new AgentCoreRuntimeUserPrincipalResolver()
      : await CognitoJwtPrincipalResolver.create({
          userPoolId: config.cognitoUserPoolId!,
          clientId: config.cognitoClientIds,
          tokenUse: config.cognitoTokenUse,
        });
  const abortController = new AbortController();
  const stageExecutor = new EngineGraphStageExecutor({
    workspaceResolver,
    outputPublisher,
    memory,
    modelCredentials: new SecretsManagerModelCredentialResolver({
      secretPrefix: config.modelSecretPrefix,
      region: config.region,
    }),
  });
  const executor = new DurableBoundaryExecutor({
    store,
    artifactStore,
    stageExecutor,
    telemetry: createAgentCoreHostedTelemetry(),
    workerId:
      process.env['AWS_AGENTCORE_RUNTIME_SESSION_ID'] ??
      `agentcore-runtime-${process.pid}`,
  });
  const runtime = new AgentCoreHttpRuntime({
    store,
    executor,
    principalResolver,
    actorIdDeriver: new KmsHmacActorIdDeriver({
      keyId: config.actorHmacKeyId,
      client: macClient,
    }),
    memory,
    shutdownSignal: abortController.signal,
  });
  return {
    server: createAgentCoreNodeServer({ runtime }),
    abortController,
  };
}

export async function main(): Promise<void> {
  const config = loadProductionConfig();
  const { server, abortController } = await composeProductionServer(config);
  installGracefulShutdown({
    server,
    abortController,
    graceMs: config.shutdownGraceMs,
  });
  const address = await listen(server, config.port, config.host);
  console.log(
    JSON.stringify({
      level: 'info',
      event: 'runtime_listening',
      host: address.host,
      port: address.port,
      health: '/ping',
    }),
  );
}
