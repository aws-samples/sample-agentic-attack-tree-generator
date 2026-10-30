import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import type { RunGraphOptions } from '@threatforest/engine';
import type { StageExecutionContext } from '../src/contracts.js';
import { EngineGraphStageExecutor } from '../src/engine-adapter.js';
import {
  AUTHORITATIVE_THREAT_INPUTS_MANIFEST,
  INGESTION_WORKSPACE_MANIFEST,
  S3IngestionWorkspaceResolver,
  WORKSPACE_CHECKPOINT_CONTENT_TYPE,
  type IngestionManifestClient,
  type IngestionObjectClient,
  type ManifestGetInput,
  type NormalizedObjectGetInput,
  type NormalizedObjectGetOutput,
  type WorkspaceCheckpointClient,
  type WorkspaceCheckpointPutInput,
} from '../src/s3-ingestion-workspace.js';

const ownerId = 'usr_owner-a';
const applicationId = 'app_application-a';
const tableName = 'threatforest-state';
const bucketName = 'threatforest-artifacts';

class FakeManifestClient implements IngestionManifestClient {
  readonly calls: ManifestGetInput[] = [];
  readonly manifests = new Map<string, unknown>();

  async getManifest(input: ManifestGetInput): Promise<{ item: unknown | null }> {
    this.calls.push(input);
    return { item: this.manifests.get(input.sortKey) ?? null };
  }

  set(manifest: Record<string, unknown>): void {
    const uploadId = manifest['uploadId'];
    if (typeof uploadId !== 'string') {
      throw new Error('test manifest requires an uploadId');
    }
    this.manifests.set(
      `UPLOAD#${Buffer.from(uploadId).toString('base64url')}#MANIFEST`,
      { entity: 'upload_manifest', manifest },
    );
  }
}

class FakeObjectClient implements IngestionObjectClient {
  readonly calls: NormalizedObjectGetInput[] = [];
  readonly objects = new Map<string, NormalizedObjectGetOutput>();

  async getNormalizedObject(
    input: NormalizedObjectGetInput,
  ): Promise<NormalizedObjectGetOutput | null> {
    this.calls.push(input);
    return this.objects.get(input.key) ?? null;
  }

  set(
    uploadId: string,
    objectId: string,
    body: Uint8Array,
    options: {
      format?: string;
      inputClass?: string;
      sha256?: string;
      contentType?: string;
    } = {},
  ): void {
    const contentType = options.contentType ?? 'text/plain; charset=utf-8';
    this.objects.set(normalizedKey(uploadId, objectId), {
      body,
      contentLength: body.byteLength,
      contentType,
      metadata: {
        sha256: options.sha256 ?? sha256(body),
        'artifact-format': options.format ?? 'text',
        'input-class': options.inputClass ?? 'evidence',
      },
    });
  }
}

class FakeCheckpointClient implements WorkspaceCheckpointClient {
  readonly objects = new Map<
    string,
    {
      body: Uint8Array;
      contentType: string;
      metadata: Readonly<Record<string, string>>;
    }
  >();
  readonly puts: WorkspaceCheckpointPutInput[] = [];

  async getObject(
    input: NormalizedObjectGetInput,
  ): Promise<NormalizedObjectGetOutput | null> {
    const object = this.objects.get(input.key);
    return object === undefined
      ? null
      : {
          body: Buffer.from(object.body),
          contentLength: object.body.byteLength,
          contentType: object.contentType,
          metadata: object.metadata,
        };
  }

  async putObject(input: WorkspaceCheckpointPutInput): Promise<void> {
    this.puts.push({ ...input, body: Buffer.from(input.body) });
    if (this.objects.has(input.key)) {
      const error = new Error('immutable object already exists');
      error.name = 'PreconditionFailed';
      throw error;
    }
    this.objects.set(input.key, {
      body: Buffer.from(input.body),
      contentType: input.contentType,
      metadata: { ...input.metadata },
    });
  }
}

test('materializes source and explicit threat uploads with exact AWS scopes and integrity metadata', async () => {
  await withWorkspace(async (workspaceRoot) => {
    const manifests = new FakeManifestClient();
    const objects = new FakeObjectClient();
    manifests.set(manifest('upload-source', ['text-source', 'markdown-source']));
    manifests.set(manifest('upload-threat', ['markdown-threat'], ['markdown-threat']));
    objects.set(
      'upload-source',
      'text-source',
      Buffer.from('service uses API Gateway\n'),
      { format: 'text' },
    );
    objects.set(
      'upload-source',
      'markdown-source',
      Buffer.from('# Architecture\n'),
      { format: 'markdown' },
    );
    objects.set(
      'upload-threat',
      'markdown-threat',
      Buffer.from('# Authoritative threats\n'),
      { format: 'markdown', inputClass: 'authoritative-threat' },
    );
    const resolver = resolverFor(workspaceRoot, manifests, objects);

    const workspace = await resolver.resolve(
      contextFor('run-one', ['upload-source'], 'upload-threat'),
    );

    const sourceFiles = await readdir(workspace.repoPath);
    assert.equal(sourceFiles.length, 3);
    assert.deepEqual(sourceFiles, [...sourceFiles].sort());
    assert.equal(sourceFiles.every((filename) => !filename.includes('/')), true);
    assert.equal(
      await readFile(
        join(
          workspace.repoPath,
          sourceFiles.find((filename) => filename.endsWith('markdown-threat.md'))!,
        ),
        'utf8',
      ),
      '# Authoritative threats\n',
    );

    assert.deepEqual(
      manifests.calls.map((call) => ({
        tableName: call.tableName,
        partitionKey: call.partitionKey,
        sortKey: call.sortKey,
      })),
      [
        {
          tableName,
          partitionKey:
            `OWNER#${Buffer.from(ownerId).toString('base64url')}` +
            `#APP#${Buffer.from(applicationId).toString('base64url')}`,
          sortKey:
            `UPLOAD#${Buffer.from('upload-source').toString('base64url')}#MANIFEST`,
        },
        {
          tableName,
          partitionKey:
            `OWNER#${Buffer.from(ownerId).toString('base64url')}` +
            `#APP#${Buffer.from(applicationId).toString('base64url')}`,
          sortKey:
            `UPLOAD#${Buffer.from('upload-threat').toString('base64url')}#MANIFEST`,
        },
      ],
    );
    assert.deepEqual(
      objects.calls.map((call) => call.key),
      [
        normalizedKey('upload-source', 'markdown-source'),
        normalizedKey('upload-source', 'text-source'),
        normalizedKey('upload-threat', 'markdown-threat'),
      ],
    );
    assert.equal(objects.calls.every((call) => call.bucketName === bucketName), true);

    const fullManifest = JSON.parse(
      await readFile(
        join(workspace.runDir!, 'input', INGESTION_WORKSPACE_MANIFEST),
        'utf8',
      ),
    ) as {
      files: Array<{
        relative_path: string;
        source_roles: string[];
        authoritative_threat_input: boolean;
        sha256: string;
      }>;
    };
    assert.equal(fullManifest.files.length, 3);
    assert.equal(fullManifest.files.every((file) => /^[a-f0-9]{64}$/.test(file.sha256)), true);
    assert.deepEqual(
      fullManifest.files.find((file) =>
        file.relative_path.endsWith('markdown-threat.md'),
      )?.source_roles,
      ['threat'],
    );

    const authoritative = JSON.parse(
      await readFile(
        join(
          workspace.runDir!,
          'input',
          AUTHORITATIVE_THREAT_INPUTS_MANIFEST,
        ),
        'utf8',
      ),
    ) as {
      threat_artifact_id: string;
      files: Array<{ relative_path: string; authoritative_threat_input: boolean }>;
    };
    assert.equal(authoritative.threat_artifact_id, 'upload-threat');
    assert.equal(authoritative.files.length, 1);
    assert.equal(authoritative.files[0]?.authoritative_threat_input, true);
    assert.match(authoritative.files[0]!.relative_path, /markdown-threat\.md$/);
  });
});

test('forwards materialized authoritative threat inputs from S3 into the engine graph', async () => {
  await withWorkspace(async (workspaceRoot) => {
    const manifests = new FakeManifestClient();
    const objects = new FakeObjectClient();
    manifests.set(manifest('upload-source', ['source-object']));
    manifests.set(
      manifest('upload-threat', ['threat-object'], ['threat-object']),
    );
    objects.set(
      'upload-source',
      'source-object',
      Buffer.from('service architecture'),
    );
    objects.set(
      'upload-threat',
      'threat-object',
      Buffer.from('# Supplied threat\n'),
      { format: 'markdown', inputClass: 'authoritative-threat' },
    );
    const resolver = resolverFor(workspaceRoot, manifests, objects);
    let receivedRepoPath: string | null = null;
    let receivedOptions: RunGraphOptions | null = null;
    const adapter = new EngineGraphStageExecutor({
      workspaceResolver: resolver,
      graphRunner: async (repoPath, options) => {
        if (options === undefined) {
          throw new Error('graph options were not provided');
        }
        receivedRepoPath = repoPath;
        receivedOptions = options;
        options.onNodeEvent?.({ phase: 'complete', nodeId: 'scanner' });
        return {
          status: 'success',
          output_dir: join(options.runDir!, 'output'),
          completed_nodes: ['scanner'],
        };
      },
    });

    const result = await adapter.execute(
      contextFor('run-authoritative', ['upload-source'], 'upload-threat'),
    );

    assert.equal(result.status, 'completed');
    assert.notEqual(receivedRepoPath, null);
    const capturedOptions = receivedOptions as RunGraphOptions | null;
    if (capturedOptions === null) {
      assert.fail('engine graph options were not captured');
    }
    const authoritativePaths =
      capturedOptions.authoritativeThreatInputPaths ?? [];
    assert.equal(authoritativePaths.length, 1);
    assert.equal(
      authoritativePaths[0]?.startsWith(`${receivedRepoPath!}/`),
      true,
    );
    assert.equal(
      await readFile(authoritativePaths[0]!, 'utf8'),
      '# Supplied threat\n',
    );
  });
});

test('refreshes a run source snapshot without deleting engine state and isolates other runs', async () => {
  await withWorkspace(async (workspaceRoot) => {
    const manifests = new FakeManifestClient();
    const objects = new FakeObjectClient();
    manifests.set(manifest('upload-source', ['text-a', 'text-stale']));
    objects.set('upload-source', 'text-a', Buffer.from('current'));
    objects.set('upload-source', 'text-stale', Buffer.from('stale'));
    const resolver = resolverFor(workspaceRoot, manifests, objects);
    const first = await resolver.resolve(contextFor('run-one', ['upload-source']));
    await writeFile(join(first.runDir!, 'state-kept.json'), '{}\n');
    assert.equal((await readdir(first.repoPath)).length, 2);

    manifests.set(manifest('upload-source', ['text-a']));
    const refreshed = await resolver.resolve(
      contextFor('run-one', ['upload-source']),
    );
    assert.equal(refreshed.repoPath, first.repoPath);
    assert.equal(refreshed.runDir, first.runDir);
    assert.equal((await readdir(refreshed.repoPath)).length, 1);
    assert.equal(await readFile(join(refreshed.runDir!, 'state-kept.json'), 'utf8'), '{}\n');

    const otherRun = await resolver.resolve(
      contextFor('run-two', ['upload-source']),
    );
    assert.notEqual(otherRun.repoPath, first.repoPath);
    assert.notEqual(otherRun.runDir, first.runDir);
    await writeFile(join(otherRun.repoPath, 'other-run-only.txt'), 'other');
    assert.equal((await readdir(first.repoPath)).includes('other-run-only.txt'), false);
  });
});

test('restores a completed engine workspace in a replacement runtime without rerunning the graph', async () => {
  const durable = new FakeCheckpointClient();
  const manifests = new FakeManifestClient();
  const objects = new FakeObjectClient();
  manifests.set(manifest('upload-source', ['source-object']));
  objects.set('upload-source', 'source-object', Buffer.from('architecture'));

  await withWorkspace(async (firstRoot) => {
    const firstResolver = resolverFor(
      firstRoot,
      manifests,
      objects,
      durable,
    );
    const firstContext = contextFor(
      'run-replacement',
      ['upload-source'],
    );
    const firstWorkspace = await firstResolver.resolve(firstContext);
    await mkdir(join(firstWorkspace.runDir!, 'state'), { recursive: true });
    await writeFile(
      join(firstWorkspace.runDir!, 'state', 'scanner_context.json'),
      '{"services":["Lambda"]}\n',
    );
    const artifact = await firstResolver.checkpoint!(
      firstContext,
      firstWorkspace,
      'completed',
    );

    assert.equal(artifact.kind, 'checkpoint');
    assert.equal(
      artifact.content_type,
      WORKSPACE_CHECKPOINT_CONTENT_TYPE,
    );
    assert.equal(
      durable.puts.every(
        (put) =>
          put.kmsKeyId === 'kms-workspace-key' &&
          /^[a-f0-9]{64}$/.test(put.checksumSha256),
      ),
      true,
    );

    await withWorkspace(async (replacementRoot) => {
      const replacementResolver = resolverFor(
        replacementRoot,
        manifests,
        objects,
        durable,
      );
      let graphRuns = 0;
      const adapter = new EngineGraphStageExecutor({
        workspaceResolver: replacementResolver,
        graphRunner: async () => {
          graphRuns += 1;
          return {
            status: 'success',
            output_dir: '/tmp/unused',
            completed_nodes: ['scanner'],
          };
        },
      });

      const recovered = await adapter.recover!(
        firstContext,
        firstContext.checkpoint,
      );

      assert.equal(recovered?.status, 'completed');
      assert.equal(graphRuns, 0);
      const restored = await replacementResolver.resolve({
        ...firstContext,
        checkpoint: {
          ...firstContext.checkpoint,
          input_artifacts: [artifact],
        },
      });
      assert.equal(
        await readFile(
          join(restored.runDir!, 'state', 'scanner_context.json'),
          'utf8',
        ),
        '{"services":["Lambda"]}\n',
      );
    });
  });
});

test('hydrates an awaiting HITL workspace after a long wait in a fresh runtime', async () => {
  const durable = new FakeCheckpointClient();
  const manifests = new FakeManifestClient();
  const objects = new FakeObjectClient();
  manifests.set(manifest('upload-source', ['source-object']));
  objects.set('upload-source', 'source-object', Buffer.from('architecture'));

  await withWorkspace(async (firstRoot) => {
    const firstResolver = resolverFor(
      firstRoot,
      manifests,
      objects,
      durable,
    );
    const waiting = contextFor('run-long-hitl', ['upload-source']);
    waiting.stage = {
      id: 'interviewer',
      version: 1,
      hitlKind: 'interviewer',
      usesModel: true,
    };
    waiting.checkpoint = {
      ...waiting.checkpoint,
      stage_id: 'interviewer',
      started_at: '2026-08-19T12:00:00.000Z',
    };
    const workspace = await firstResolver.resolve(waiting);
    await mkdir(join(workspace.runDir!, 'state'), { recursive: true });
    await writeFile(
      join(workspace.runDir!, 'state', 'scanner_context.json'),
      '{"interview_seed":"committed-before-hitl"}\n',
    );
    const artifact = await firstResolver.checkpoint!(
      waiting,
      workspace,
      'awaiting_input',
    );

    await withWorkspace(async (replacementRoot) => {
      const replacement = resolverFor(
        replacementRoot,
        manifests,
        objects,
        durable,
      );
      const afterFiveMinutes = {
        ...waiting,
        run: {
          ...waiting.run,
          updated_at: '2026-08-19T12:06:00.000Z',
        },
        checkpoint: {
          ...waiting.checkpoint,
          status: 'started' as const,
          output_artifacts: [artifact],
        },
      };
      const restored = await replacement.resolve(afterFiveMinutes);
      assert.equal(
        await readFile(
          join(restored.runDir!, 'state', 'scanner_context.json'),
          'utf8',
        ),
        '{"interview_seed":"committed-before-hitl"}\n',
      );
    });
  });
});

test('rejects non-ready and cross-scope manifests before reading S3', async () => {
  await withWorkspace(async (workspaceRoot) => {
    const manifests = new FakeManifestClient();
    const objects = new FakeObjectClient();
    manifests.set({ ...manifest('upload-source', ['text-a']), status: 'normalizing' });
    const resolver = resolverFor(workspaceRoot, manifests, objects);
    await assert.rejects(
      resolver.resolve(contextFor('run-one', ['upload-source'])),
      /upload is not ready/,
    );
    assert.equal(objects.calls.length, 0);

    manifests.set({
      ...manifest('upload-source', ['text-a']),
      ownerId: 'usr_different-owner',
    });
    await assert.rejects(
      resolver.resolve(contextFor('run-one', ['upload-source'])),
      /manifest scope does not match/,
    );
    assert.equal(objects.calls.length, 0);
  });
});

test('rejects traversal identifiers, duplicate object IDs, and corrupt S3 bodies', async () => {
  await withWorkspace(async (workspaceRoot) => {
    const manifests = new FakeManifestClient();
    const objects = new FakeObjectClient();
    const resolver = resolverFor(workspaceRoot, manifests, objects);

    await assert.rejects(
      resolver.resolve(contextFor('run-one', ['../other-user'])),
      /safe .* ingestion identifier/,
    );
    manifests.set(manifest('upload-source', ['text-a', 'text-a']));
    await assert.rejects(
      resolver.resolve(contextFor('run-one', ['upload-source'])),
      /duplicate normalized object IDs/,
    );
    manifests.set(manifest('upload-source', []));
    await assert.rejects(
      resolver.resolve(contextFor('run-one', ['upload-source'])),
      /no usable normalized evidence/,
    );
    assert.equal(objects.calls.length, 0);

    manifests.set(manifest('upload-source', ['text-a']));
    objects.set('upload-source', 'text-a', Buffer.from('tampered'), {
      sha256: sha256('expected'),
    });
    await assert.rejects(
      resolver.resolve(contextFor('run-one', ['upload-source'])),
      /SHA-256 mismatch/,
    );
    assert.equal(
      (await findDirectories(workspaceRoot)).some((path) => path.endsWith('/source')),
      false,
    );
  });
});

test('refuses an injected source symlink and does not modify its target', async () => {
  await withWorkspace(async (workspaceRoot) => {
    const manifests = new FakeManifestClient();
    const objects = new FakeObjectClient();
    manifests.set(manifest('upload-source', ['text-a']));
    objects.set('upload-source', 'text-a', Buffer.from('safe'));
    const resolver = resolverFor(workspaceRoot, manifests, objects);
    const first = await resolver.resolve(contextFor('run-one', ['upload-source']));
    const target = await mkdtemp(join(workspaceRoot, 'outside-'));
    await writeFile(join(target, 'sentinel.txt'), 'untouched');
    await rm(first.repoPath, { recursive: true });
    await symlink(target, first.repoPath, 'dir');

    await assert.rejects(
      resolver.resolve(contextFor('run-one', ['upload-source'])),
      /symbolic-link source workspace/,
    );
    assert.equal(await readFile(join(target, 'sentinel.txt'), 'utf8'), 'untouched');
    assert.equal((await lstat(first.repoPath)).isSymbolicLink(), true);
  });
});

function resolverFor(
  workspaceRoot: string,
  manifestClient: IngestionManifestClient,
  objectClient: IngestionObjectClient,
  checkpointClient?: WorkspaceCheckpointClient,
): S3IngestionWorkspaceResolver {
  return new S3IngestionWorkspaceResolver({
    tableName,
    bucketName,
    workspaceRoot,
    manifestClient,
    objectClient,
    ...(checkpointClient === undefined
      ? {}
      : {
          checkpointClient,
          checkpointKmsKeyId: 'kms-workspace-key',
          checkpointKeyPrefix: 'hosted',
        }),
  });
}

function contextFor(
  runId: string,
  sourceArtifactIds: string[],
  threatArtifactId: string | null = null,
): StageExecutionContext {
  return {
    scope: {
      owner_id: ownerId,
      application_id: applicationId,
    },
    run: {
      schema_version: 1,
      owner_id: ownerId,
      application_id: applicationId,
      run_id: runId,
      status: 'running',
      source_artifact_ids: sourceArtifactIds,
      threat_artifact_id: threatArtifactId,
      current_stage_id: 'scanner',
      trace_id: 'trace-one',
      revision: 1,
      last_event_sequence: 0,
      created_at: '2026-08-19T12:00:00.000Z',
      updated_at: '2026-08-19T12:00:00.000Z',
      completed_at: null,
      error_code: null,
      error_message: null,
    },
    settings: {
      schema_version: 1,
      owner_id: ownerId,
      application_id: applicationId,
      run_id: runId,
      provider: 'bedrock',
      model_id: 'model',
      model_parameters: {},
      frameworks: ['STRIDE'],
      embeddings_model: 'embeddings',
      config_hash: 'a'.repeat(64),
      created_at: '2026-08-19T12:00:00.000Z',
    },
    stage: { id: 'scanner', version: 1, hitlKind: null, usesModel: true },
    checkpoint: {
      schema_version: 1,
      owner_id: ownerId,
      application_id: applicationId,
      run_id: runId,
      stage_id: 'scanner',
      stage_version: 1,
      status: 'started',
      attempt: 1,
      fencing_token: 1,
      idempotency_key: 'key',
      trace_id: 'trace-one-000000',
      input_artifacts: [],
      output_artifacts: [],
      model_id: 'model',
      config_hash: 'a'.repeat(64),
      started_at: '2026-08-19T12:00:00.000Z',
      completed_at: null,
      error_code: null,
      error_message: null,
    },
    actorId: 'actor',
    completedStageIds: [],
    hitlHistory: [],
    response: null,
    signal: new AbortController().signal,
    assertLease: async () => {},
  } as unknown as StageExecutionContext;
}

function manifest(
  uploadId: string,
  normalizedObjectIds: string[],
  authoritativeThreatObjectIds: string[] = [],
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    revision: 1,
    ownerId,
    applicationId,
    uploadId,
    status: 'ready',
    normalizedObjectIds,
    authoritativeThreatObjectIds,
  };
}

function normalizedKey(uploadId: string, objectId: string): string {
  return (
    `v1/owners/${ownerId}/applications/${applicationId}` +
    `/uploads/${uploadId}/normalized/${objectId}`
  );
}

function sha256(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

async function withWorkspace(
  run: (workspaceRoot: string) => Promise<void>,
): Promise<void> {
  const workspaceRoot = await mkdtemp('/tmp/threatforest-s3-resolver-test-');
  try {
    await run(workspaceRoot);
  } finally {
    await rm(workspaceRoot, { recursive: true, force: true });
  }
}

async function findDirectories(root: string): Promise<string[]> {
  const output: string[] = [];
  const queue = [root];
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const child = join(current, entry.name);
      if (entry.isDirectory()) {
        output.push(child);
        queue.push(child);
      }
    }
  }
  return output;
}
