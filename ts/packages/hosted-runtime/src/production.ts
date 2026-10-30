import { mkdir, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import type { Server } from 'node:http';
import type { WorkspaceResolver, MaterializedWorkspace } from './engine-adapter.js';
import type { StageExecutionContext } from './contracts.js';

export interface ProductionConfig {
  region: string;
  stateTableName: string;
  stateTableApplicationIndexName: string;
  artifactBucketName: string;
  artifactKmsKeyId: string;
  artifactKeyPrefix: string;
  actorHmacKeyId: string;
  memoryId: string;
  modelSecretPrefix: string;
  memoryWritePolicy: 'approved_only';
  principalMode: 'runtime_user_id' | 'cognito_jwt';
  cognitoUserPoolId: string | null;
  cognitoClientIds: readonly string[];
  cognitoTokenUse: 'id' | 'access';
  workspaceRoot: string;
  port: number;
  host: string;
  shutdownGraceMs: number;
}

function requiredEnvironment(
  environment: NodeJS.ProcessEnv,
  name: string,
): string {
  const value = environment[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

export function loadProductionConfig(
  environment: NodeJS.ProcessEnv = process.env,
): ProductionConfig {
  const memoryWritePolicy = environment['THREATFOREST_MEMORY_WRITE_POLICY'] ?? 'approved_only';
  if (memoryWritePolicy !== 'approved_only') {
    throw new Error('THREATFOREST_MEMORY_WRITE_POLICY must be approved_only');
  }
  const tokenUse = environment['THREATFOREST_COGNITO_TOKEN_USE'] ?? 'access';
  if (tokenUse !== 'id' && tokenUse !== 'access') {
    throw new Error('THREATFOREST_COGNITO_TOKEN_USE must be id or access');
  }
  const principalMode =
    environment['THREATFOREST_PRINCIPAL_MODE'] ?? 'runtime_user_id';
  if (principalMode !== 'runtime_user_id' && principalMode !== 'cognito_jwt') {
    throw new Error(
      'THREATFOREST_PRINCIPAL_MODE must be runtime_user_id or cognito_jwt',
    );
  }
  const clients = (environment['THREATFOREST_COGNITO_CLIENT_ID'] ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  const cognitoUserPoolId =
    environment['THREATFOREST_COGNITO_USER_POOL_ID']?.trim() || null;
  if (
    principalMode === 'cognito_jwt' &&
    (clients.length === 0 || cognitoUserPoolId === null)
  ) {
    throw new Error(
      'Cognito principal mode requires THREATFOREST_COGNITO_USER_POOL_ID and THREATFOREST_COGNITO_CLIENT_ID',
    );
  }
  return {
    region: environment['AWS_REGION']?.trim() || 'eu-west-2',
    stateTableName: requiredEnvironment(environment, 'THREATFOREST_STATE_TABLE'),
    stateTableApplicationIndexName:
      environment['THREATFOREST_STATE_TABLE_APPLICATION_INDEX']?.trim() || 'GSI1',
    artifactBucketName: requiredEnvironment(environment, 'THREATFOREST_ARTIFACT_BUCKET'),
    artifactKmsKeyId: requiredEnvironment(
      environment,
      'THREATFOREST_ARTIFACT_KMS_KEY_ARN',
    ),
    artifactKeyPrefix: environment['THREATFOREST_ARTIFACT_KEY_PREFIX']?.trim() || 'hosted',
    actorHmacKeyId: requiredEnvironment(
      environment,
      'THREATFOREST_ACTOR_HMAC_KEY_ARN',
    ),
    memoryId: requiredEnvironment(environment, 'THREATFOREST_MEMORY_ID'),
    modelSecretPrefix: requiredEnvironment(
      environment,
      'THREATFOREST_MODEL_SECRET_PREFIX',
    ),
    memoryWritePolicy,
    principalMode,
    cognitoUserPoolId,
    cognitoClientIds: clients,
    cognitoTokenUse: tokenUse,
    workspaceRoot: resolve(
      environment['THREATFOREST_WORKSPACE_ROOT']?.trim() ||
        '/tmp/threatforest-ingestion',
    ),
    port: positiveInteger(environment['PORT'], 8080, 'PORT'),
    host: environment['HOST']?.trim() || '0.0.0.0',
    shutdownGraceMs: positiveInteger(
      environment['THREATFOREST_SHUTDOWN_GRACE_MS'],
      25_000,
      'THREATFOREST_SHUTDOWN_GRACE_MS',
    ),
  };
}

/**
 * Resolves a pre-materialized application source tree and an isolated run
 * directory. Upload normalization/materialization populates the source tree;
 * this runtime refuses to analyze an absent or empty mount silently.
 */
export class FilesystemRuntimeWorkspaceResolver implements WorkspaceResolver {
  readonly #root: string;

  constructor(root: string) {
    this.#root = resolve(root);
  }

  async resolve(context: StageExecutionContext): Promise<MaterializedWorkspace> {
    const applicationRoot = join(
      this.#root,
      context.scope.owner_id,
      context.scope.application_id,
    );
    const repoPath = join(applicationRoot, 'source');
    let sourceStats;
    try {
      sourceStats = await stat(repoPath);
    } catch {
      throw new Error(
        `normalized source workspace is not materialized for application ${context.scope.application_id}`,
      );
    }
    if (!sourceStats.isDirectory()) {
      throw new Error(`normalized source workspace ${repoPath} is not a directory`);
    }
    const runDir = join(applicationRoot, 'runs', context.run.run_id);
    await mkdir(runDir, { recursive: true, mode: 0o700 });
    return { repoPath, runDir };
  }
}

export interface GracefulShutdownOptions {
  server: Server;
  abortController: AbortController;
  graceMs: number;
  logger?: Pick<Console, 'log' | 'error'>;
}

export function installGracefulShutdown(options: GracefulShutdownOptions): () => void {
  const logger = options.logger ?? console;
  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals): void => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    logger.log(JSON.stringify({ level: 'info', event: 'runtime_shutdown', signal }));
    options.abortController.abort(new Error(`received ${signal}`));
    options.server.close((error) => {
      if (error !== undefined) {
        logger.error(JSON.stringify({ level: 'error', event: 'server_close_failed' }), error);
        process.exitCode = 1;
      }
    });
    options.server.closeIdleConnections?.();
    const timer = setTimeout(() => {
      logger.error(
        JSON.stringify({ level: 'error', event: 'runtime_shutdown_timeout' }),
      );
      options.server.closeAllConnections?.();
      process.exitCode = 1;
    }, options.graceMs);
    timer.unref();
    options.server.once('close', () => clearTimeout(timer));
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
  return () => {
    process.off('SIGTERM', shutdown);
    process.off('SIGINT', shutdown);
  };
}
