import assert from 'node:assert/strict';
import {
  mkdir,
  mkdtemp,
  rm,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import {
  ApplicationIdSchema,
  RunIdSchema,
  UserIdSchema,
  runDisplayName,
} from '@threatforest/types';
import type { StageExecutionContext } from '../src/contracts.js';
import { EngineGraphStageExecutor } from '../src/engine-adapter.js';
import type { HostedTelemetryEvent } from '../src/telemetry.js';
import {
  createDynamoHostedVersionStateClient,
  HostedReportOutputPublisher,
  type AwsCommandClient,
  type HostedVersionDynamoCommands,
  type HostedVersionStateClient,
  type PublishedObjectClient,
  type PublishedObjectHead,
  type PublishedObjectPutInput,
} from '../src/output-publisher.js';

const ownerId = UserIdSchema.parse('usr_report_owner');
const applicationId = ApplicationIdSchema.parse('app_report_application');
const runId = RunIdSchema.parse('run_report_publication');

class FakeObjectClient implements PublishedObjectClient {
  readonly calls: PublishedObjectPutInput[] = [];
  readonly objects = new Map<
    string,
    { input: PublishedObjectPutInput; head: PublishedObjectHead }
  >();

  async putObjectIfAbsent(input: PublishedObjectPutInput): Promise<boolean> {
    this.calls.push({ ...input, body: Buffer.from(input.body) });
    if (this.objects.has(input.key)) {
      return false;
    }
    this.objects.set(input.key, {
      input: { ...input, body: Buffer.from(input.body) },
      head: {
        sizeBytes: input.body.byteLength,
        metadata: { ...input.metadata },
        serverSideEncryption: 'aws:kms',
        kmsKeyId: input.kmsKeyId,
        bucketKeyEnabled: true,
      },
    });
    return true;
  }

  async headObject(
    _bucketName: string,
    key: string,
  ): Promise<PublishedObjectHead | null> {
    return this.objects.get(key)?.head ?? null;
  }

  async getObject(
    _bucketName: string,
    key: string,
  ): Promise<Uint8Array | null> {
    return this.objects.get(key)?.input.body ?? null;
  }
}

class FakeVersionClient implements HostedVersionStateClient {
  readonly items = new Map<string, Readonly<Record<string, unknown>>>();
  applicationReport: Readonly<Record<string, unknown>> | null = null;
  putCalls = 0;
  applicationReportPutCalls = 0;
  listCalls = 0;
  readonly expectedVersionDigests: Array<string | null> = [];

  async getVersion(
    _tableName: string,
    partitionKey: string,
    sortKey: string,
  ): Promise<unknown | null> {
    return this.items.get(`${partitionKey}\0${sortKey}`) ?? null;
  }

  async putVersionIfAbsent(
    _tableName: string,
    item: Readonly<Record<string, unknown>>,
  ): Promise<boolean> {
    this.putCalls += 1;
    const key = `${String(item['PK'])}\0${String(item['SK'])}`;
    if (this.items.has(key)) {
      return false;
    }
    this.items.set(key, structuredClone(item));
    return true;
  }

  async listVersions(
    _tableName: string,
    partitionKey: string,
  ): Promise<readonly unknown[]> {
    this.listCalls += 1;
    return [...this.items.entries()]
      .filter(([key]) => key.startsWith(`${partitionKey}\0VERSION#`))
      .map(([, item]) => structuredClone(item));
  }

  async getApplicationExportContext() {
    return {
      name: 'Payments',
      description: 'Payment processing',
      createdAt: '2026-08-01T00:00:00.000Z',
      businessContext: {
        description: 'Payment processing',
        critical_assets: ['card data'],
      },
    };
  }

  async getApplicationReport(): Promise<unknown | null> {
    return this.applicationReport === null
      ? null
      : structuredClone(this.applicationReport);
  }

  async putApplicationReport(
    _tableName: string,
    item: Readonly<Record<string, unknown>>,
    expectedVersionDigest: string | null,
  ): Promise<boolean> {
    this.applicationReportPutCalls += 1;
    this.expectedVersionDigests.push(expectedVersionDigest);
    const currentDigest =
      typeof this.applicationReport?.['version_digest'] === 'string'
        ? this.applicationReport['version_digest']
        : null;
    const nextDigest = String(item['version_digest']);
    if (
      currentDigest !== expectedVersionDigest &&
      currentDigest !== nextDigest
    ) {
      return false;
    }
    this.applicationReport = structuredClone(item);
    return true;
  }
}

class RacingVersionClient extends FakeVersionClient {
  conflictPending = true;

  override async putApplicationReport(
    tableName: string,
    item: Readonly<Record<string, unknown>>,
    expectedVersionDigest: string | null,
  ): Promise<boolean> {
    if (this.conflictPending) {
      this.conflictPending = false;
      this.applicationReportPutCalls += 1;
      this.expectedVersionDigests.push(expectedVersionDigest);
      this.applicationReport = {
        ...structuredClone(item),
        version_digest: 'f'.repeat(64),
      };
      return false;
    }
    return super.putApplicationReport(
      tableName,
      item,
      expectedVersionDigest,
    );
  }
}

test('report_verifier publishes encrypted outputs and an idempotent hosted version receipt', async () => {
  await withRunDirectory(async (runDir) => {
    const objectClient = new FakeObjectClient();
    const versionClient = new FakeVersionClient();
    const publisher = new HostedReportOutputPublisher({
      tableName: 'threatforest-state',
      bucketName: 'threatforest-artifacts',
      kmsKeyId: 'arn:aws:kms:eu-west-2:123:key/artifacts',
      keyPrefix: 'hosted',
      objectClient,
      versionClient,
    });
    const context = reportContext();
    const adapter = new EngineGraphStageExecutor({
      workspaceResolver: {
        async resolve() {
          return { repoPath: join(runDir, 'source'), runDir };
        },
      },
      outputPublisher: publisher,
      graphRunner: async (_repoPath, options) => {
        if (options === undefined) {
          throw new Error('graph options were not provided');
        }
        options.onNodeEvent?.({
          phase: 'complete',
          nodeId: 'report_verifier',
        });
        return {
          status: 'interrupted',
          output_dir: join(runDir, 'output'),
          completed_nodes: ['report_verifier'],
        };
      },
    });

    const first = await adapter.execute(context);
    const second = await adapter.execute(context);
    assert.equal(versionClient.applicationReport, null);
    assert.equal(versionClient.listCalls, 0, 'completion must not read version history');
    await publisher.ensureApplicationReport(context.scope);
    const writes = objectClient.calls.length;
    await publisher.ensureApplicationReport(context.scope);
    assert.equal(objectClient.calls.length, writes, 'cached export must not rebuild');

    assert.equal(first.status, 'completed');
    assert.equal(second.status, 'completed');
    if (first.status !== 'completed' || second.status !== 'completed') {
      assert.fail('report verifier did not complete');
    }
    assert.equal(first.outputArtifacts?.length, 1);
    assert.deepEqual(second.outputArtifacts, first.outputArtifacts);
    assert.equal(
      first.outputArtifacts?.every((artifact) => artifact.kind === 'report'),
      true,
    );
    assert.equal(objectClient.objects.size, 11);
    assert.equal(objectClient.calls.length, 20);
    assert.equal(
      objectClient.calls.every(
        (call) =>
          call.bucketName === 'threatforest-artifacts' &&
          call.kmsKeyId === 'arn:aws:kms:eu-west-2:123:key/artifacts' &&
          /^[a-f0-9]{64}$/.test(call.checksumSha256),
      ),
      true,
    );
    assert.deepEqual(
      [...objectClient.objects.keys()].sort(),
      [
        `hosted/owners/${ownerId}/applications/${applicationId}/reports/full-${String(
          versionClient.applicationReport?.['version_digest'],
        )}-without-scanner.tfreport`,
        `hosted/owners/${ownerId}/applications/${applicationId}/reports/full-${String(
          versionClient.applicationReport?.['version_digest'],
        )}.tfreport`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/output/threat_model_report.md`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/output/threatforest_data.json`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/reports/version-without-scanner.tfreport`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/reports/version.tfreport`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/state/attack_trees.json`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/state/mitigations.json`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/state/scanner_context.json`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/state/threats.json`,
        `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/state/ttp_mappings.json`,
      ],
    );
    assert.equal(versionClient.items.size, 1);
    assert.equal(versionClient.putCalls, 2);
    const item = [...versionClient.items.values()][0]!;
    assert.equal(
      item['PK'],
      `HOSTED#OWNER#${Buffer.from(ownerId).toString('base64url')}` +
        `#APP#${Buffer.from(applicationId).toString('base64url')}`,
    );
    assert.equal(
      item['SK'],
      `VERSION#${Buffer.from(runId).toString('base64url')}`,
    );
    assert.deepEqual(item['summary'], {
      id: runId,
      run_date: context.run.created_at,
      status: 'complete',
      threat_count: 3,
      high_severity_count: 2,
      categories: ['Spoofing', 'Tampering'],
      display_name: runDisplayName(null, context.run.created_at),
      run_id: runId,
    });
    assert.equal(
      item['data_key'],
      `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/output/threatforest_data.json`,
    );
    const versionReport = item['report'] as Record<string, unknown>;
    assert.equal(
      versionReport['key'],
      `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/reports/version.tfreport`,
    );
    assert.equal(versionReport['content_type'], 'application/zip');
    assert.match(String(versionReport['filename']), /\.tfreport$/);
    assert.equal(
      (item['bundle_entries'] as unknown[]).length,
      7,
    );
    assert.equal(
      versionClient.applicationReport?.['version_count'],
      1,
    );
    const fullReport = versionClient.applicationReport?.['report'] as
      | Record<string, unknown>
      | undefined;
    assert.equal(fullReport?.['content_type'], 'application/zip');
    assert.ok(versionClient.applicationReport?.['report_without_scanner']);

    const single = objectClient.objects.get(
      `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/reports/version.tfreport`,
    )!.input.body;
    const entries = zipEntries(single);
    assert.ok(entries.has('threatforest_report.json'));
    assert.ok(entries.has('application/metadata.json'));
    assert.ok(entries.has('application/business_context.json'));
    assert.ok(
      entries.has(
        `versions/${runId}/output/threatforest_data.json`,
      ),
    );
    const manifest = JSON.parse(
      Buffer.from(entries.get('threatforest_report.json')!).toString('utf8'),
    ) as Record<string, unknown>;
    assert.equal(manifest['source_app_name'], 'Payments');
    assert.deepEqual(manifest['versions'], [runId]);
    assert.ok(
      entries.has(`versions/${runId}/state/scanner_context.json`),
    );
    const withoutScanner = objectClient.objects.get(
      `hosted/owners/${ownerId}/applications/${applicationId}/runs/${runId}/reports/version-without-scanner.tfreport`,
    )!.input.body;
    const withoutEntries = zipEntries(withoutScanner);
    assert.equal(
      withoutEntries.has(`versions/${runId}/state/scanner_context.json`),
      false,
    );
    const withoutManifest = JSON.parse(
      Buffer.from(
        withoutEntries.get('threatforest_report.json')!,
      ).toString('utf8'),
    ) as Record<string, unknown>;
    assert.equal(withoutManifest['include_scanner_context'], false);
  });
});

test('report publication rejects an existing output with different content', async () => {
  await withRunDirectory(async (runDir) => {
    const objectClient = new FakeObjectClient();
    const versionClient = new FakeVersionClient();
    const publisher = new HostedReportOutputPublisher({
      tableName: 'threatforest-state',
      bucketName: 'threatforest-artifacts',
      kmsKeyId: 'alias/artifacts',
      objectClient,
      versionClient,
    });
    await publisher.publish(reportContext(), runDir, join(runDir, 'source'));
    const dataKey = [...objectClient.objects.keys()].find((key) =>
      key.endsWith('/threatforest_data.json'),
    )!;
    objectClient.objects.get(dataKey)!.head = {
      sizeBytes: 1,
      metadata: { sha256: '0'.repeat(64) },
    };

    await assert.rejects(
      publisher.publish(reportContext(), runDir, join(runDir, 'source')),
      /contains different content/,
    );
    assert.equal(versionClient.items.size, 1);
  });
});

test('completed report publication emits idempotent domain quality metrics', async () => {
  await withRunDirectory(async (runDir) => {
    await writeQualityState(runDir);
    const events: HostedTelemetryEvent[] = [];
    const objectClient = new FakeObjectClient();
    const versionClient = new FakeVersionClient();
    const publisher = new HostedReportOutputPublisher({
      tableName: 'threatforest-state',
      bucketName: 'threatforest-artifacts',
      kmsKeyId: 'alias/artifacts',
      objectClient,
      versionClient,
      telemetry: {
        record(event) {
          events.push(event);
        },
      },
    });

    await publisher.publish(reportContext(), runDir, join(runDir, 'source'));
    await publisher.publish(reportContext(), runDir, join(runDir, 'source'));

    assert.equal(events.length, 1);
    assert.equal(events[0]?.spanName, 'threatforest.run.output_quality');
    assert.equal(events[0]?.status, 'ok');
    assert.deepEqual(events[0]?.attributes, {
      'threatforest.application.id': applicationId,
      'threatforest.run.id': runId,
      'threatforest.run.correlation_id':
        '0123456789abcdef0123456789abcdef',
      'threatforest.model.provider': 'bedrock',
      'threatforest.model.id': 'model',
      'threatforest.ttp.frameworks': ['STRIDE'],
      'threatforest.run.outcome': 'completed',
      'gen_ai.provider.name': 'bedrock',
      'gen_ai.request.model': 'model',
      'threatforest.quality.schema_version': '1.1.0',
      'threatforest.quality.gate_passed': true,
      'threatforest.quality.issue_count': 0,
      'threatforest.evaluation.ready': true,
      'threatforest.threat.count': 3,
      'threatforest.threat.high_severity_count': 2,
      'threatforest.threat.categories': ['Spoofing', 'Tampering'],
      'threatforest.ttp.accepted_precision_target': 0.7,
      'threatforest.ttp.acceptance_policy': 'similarity-margin-v1',
      'threatforest.ttp.decision_coverage': 1,
      'threatforest.ttp.accepted_coverage': 0.5,
      'threatforest.ttp.abstention_rate': 0.5,
      'threatforest.mitigation.coverage': 1,
      'threatforest.mitigation.evidence_coverage': 1,
      'threatforest.ttp.mean_accepted_confidence': 0.82,
    });
    const item = [...versionClient.items.values()][0]!;
    assert.equal(
      (item['output_quality'] as { gatePassed: boolean }).gatePassed,
      true,
    );
  });
});

test('publication fails closed on fabricated evidence even without telemetry', async () => {
  await withRunDirectory(async (runDir) => {
    const objects = new FakeObjectClient();
    const versions = new FakeVersionClient();
    const publisher = new HostedReportOutputPublisher({
      tableName: 'state', bucketName: 'artifacts', kmsKeyId: 'key',
      objectClient: objects, versionClient: versions,
    });
    await writeFile(join(runDir, 'source', 'infra', 'storage.ts'), 'No such quoted configuration.\n');
    await assert.rejects(
      publisher.publish(reportContext(), runDir, join(runDir, 'source')),
      /domain quality gate.*unverifiable evidence/,
    );
    assert.equal(objects.calls.length, 0);
    assert.equal(versions.items.size, 0);
  });
});

test('version export uses the run business context rather than later application metadata', async () => {
  await withRunDirectory(async (runDir) => {
    const objects = new FakeObjectClient();
    const publisher = new HostedReportOutputPublisher({
      tableName: 'state', bucketName: 'artifacts', kmsKeyId: 'key',
      objectClient: objects, versionClient: new FakeVersionClient(),
    });
    const context = reportContext();
    const businessContext = {
      description: 'Context at the time this run started.', regulatory_frameworks: ['PCI DSS'],
      data_sensitivity: 'regulated_financial' as const,
      cia_priority: ['availability', 'integrity', 'confidentiality'] as ('availability' | 'integrity' | 'confidentiality')[],
    };
    await publisher.publish({
      ...context, settings: { ...context.settings, business_context: businessContext },
    }, runDir, join(runDir, 'source'));
    const archive = [...objects.objects.entries()].find(([key]) => key.endsWith('/reports/version.tfreport'))![1].input.body;
    const entries = zipEntries(archive);
    assert.deepEqual(JSON.parse(Buffer.from(entries.get('application/business_context.json')!).toString('utf8')), businessContext);
  });
});

test('full application report contains every completed immutable version', async () => {
  const objectClient = new FakeObjectClient();
  const versionClient = new FakeVersionClient();
  const publisher = new HostedReportOutputPublisher({
    tableName: 'threatforest-state',
    bucketName: 'threatforest-artifacts',
    kmsKeyId: 'alias/artifacts',
    objectClient,
    versionClient,
  });
  const earlierRun = RunIdSchema.parse('run_report_earlier');
  await withRunDirectory((runDir) =>
    publisher.publish(
      reportContext(earlierRun, '2026-08-18T12:00:00.000Z'),
      runDir,
      join(runDir, 'source'),
    ).then(() => undefined),
  );
  await withRunDirectory((runDir) =>
    publisher.publish(reportContext(), runDir, join(runDir, 'source')).then(() => undefined),
  );

  await publisher.ensureApplicationReport(reportContext().scope);
  assert.equal(versionClient.applicationReport?.['version_count'], 2);
  const report = versionClient.applicationReport?.['report'] as Record<
    string,
    unknown
  >;
  const full = objectClient.objects.get(String(report['key']))!.input.body;
  const entries = zipEntries(full);
  const manifest = JSON.parse(
    Buffer.from(entries.get('threatforest_report.json')!).toString('utf8'),
  ) as Record<string, unknown>;
  assert.deepEqual(manifest['versions'], [earlierRun, runId]);
  assert.ok(
    entries.has(`versions/${earlierRun}/output/threatforest_data.json`),
  );
  assert.ok(entries.has(`versions/${runId}/output/threatforest_data.json`));
});

test('report Memory writes are best-effort after durable report publication', async () => {
  await withRunDirectory(async (runDir) => {
    const objectClient = new FakeObjectClient();
    const versionClient = new FakeVersionClient();
    const logged: unknown[][] = [];
    const publisher = new HostedReportOutputPublisher({
      tableName: 'threatforest-state',
      bucketName: 'threatforest-artifacts',
      kmsKeyId: 'alias/artifacts',
      objectClient,
      versionClient,
      memory: {
        async recordApprovedFeedback() {},
        async recordThreatModel() {
          throw new Error('memory unavailable');
        },
        async retrieveApplicationContext() {
          return [];
        },
      },
      logger: {
        error(...values: unknown[]) {
          logged.push(values);
        },
      },
    });

    const artifacts = await publisher.publish(reportContext(), runDir, join(runDir, 'source'));

    assert.equal(artifacts.length, 1);
    assert.equal(versionClient.items.size, 1);
    assert.equal(versionClient.applicationReport, null);
    assert.equal(logged.length, 1);
    assert.deepEqual(JSON.parse(String(logged[0]?.[0])), {
      level: 'error',
      event: 'agentcore_memory_write_failed',
      operation: 'record_threat_model',
      application_id: applicationId,
      run_id: runId,
    });
    assert.match(String(logged[0]?.[1]), /memory unavailable/);
  });
});

test('application report publication rebuilds after an equal-count digest conflict', async () => {
  await withRunDirectory(async (runDir) => {
    const objectClient = new FakeObjectClient();
    const versionClient = new RacingVersionClient();
    const publisher = new HostedReportOutputPublisher({
      tableName: 'threatforest-state',
      bucketName: 'threatforest-artifacts',
      kmsKeyId: 'alias/artifacts',
      objectClient,
      versionClient,
    });

    await publisher.publish(reportContext(), runDir, join(runDir, 'source'));
    await publisher.ensureApplicationReport(reportContext().scope);

    assert.equal(versionClient.applicationReportPutCalls, 2);
    assert.equal(versionClient.listCalls, 3);
    assert.deepEqual(versionClient.expectedVersionDigests, [
      null,
      'f'.repeat(64),
    ]);
    assert.notEqual(
      versionClient.applicationReport?.['version_digest'],
      'f'.repeat(64),
    );
    assert.equal(versionClient.applicationReport?.['version_count'], 1);
  });
});

test('Dynamo version enumeration paginates and application reports use digest CAS', async () => {
  class Get {
    constructor(readonly input: Record<string, unknown>) {}
  }
  class Put {
    constructor(readonly input: Record<string, unknown>) {}
  }
  class Query {
    constructor(readonly input: Record<string, unknown>) {}
  }
  const sent: unknown[] = [];
  const client: AwsCommandClient = {
    async send(command) {
      sent.push(command);
      if (command instanceof Query) {
        return command.input['ExclusiveStartKey'] === undefined
          ? {
              Items: [{ run_id: 'run-page-1' }],
              LastEvaluatedKey: { PK: 'partition', SK: 'VERSION#page-1' },
            }
          : { Items: [{ run_id: 'run-page-2' }] };
      }
      return {};
    },
  };
  const state = createDynamoHostedVersionStateClient(
    client,
    {
      GetCommand: Get,
      PutCommand: Put,
      QueryCommand: Query,
    } as HostedVersionDynamoCommands,
  );

  const versions = await state.listVersions('table', 'partition');
  assert.deepEqual(versions, [
    { run_id: 'run-page-1' },
    { run_id: 'run-page-2' },
  ]);
  const queries = sent.filter((command) => command instanceof Query) as Query[];
  assert.equal(queries.length, 2);
  assert.equal(queries[0]?.input['ExclusiveStartKey'], undefined);
  assert.deepEqual(queries[1]?.input['ExclusiveStartKey'], {
    PK: 'partition',
    SK: 'VERSION#page-1',
  });

  const expected = 'a'.repeat(64);
  const next = 'b'.repeat(64);
  assert.equal(
    await state.putApplicationReport(
      'table',
      {
        PK: 'partition',
        SK: 'APPLICATION_REPORT',
        version_digest: next,
      },
      expected,
    ),
    true,
  );
  const put = sent.find((command) => command instanceof Put) as Put;
  assert.equal(
    put.input['ConditionExpression'],
    'version_digest = :expectedVersionDigest OR version_digest = :nextVersionDigest',
  );
  assert.deepEqual(put.input['ExpressionAttributeValues'], {
    ':nextVersionDigest': next,
    ':expectedVersionDigest': expected,
  });
  assert.equal(String(put.input['ConditionExpression']).includes('version_count'), false);
});

function reportContext(
  selectedRunId = runId,
  createdAt = '2026-08-19T12:00:00.000Z',
): StageExecutionContext {
  return {
    scope: { owner_id: ownerId, application_id: applicationId },
    run: {
      schema_version: 1,
      owner_id: ownerId,
      application_id: applicationId,
      run_id: selectedRunId,
      status: 'running',
      source_artifact_ids: [],
      threat_artifact_id: null,
      current_stage_id: 'report_verifier',
      trace_id: '0123456789abcdef0123456789abcdef',
      revision: 2,
      last_event_sequence: 4,
      created_at: createdAt,
      updated_at: createdAt,
      completed_at: null,
      error_code: null,
      error_message: null,
    },
    settings: {
      schema_version: 1,
      owner_id: ownerId,
      application_id: applicationId,
      run_id: selectedRunId,
      provider: 'bedrock',
      model_id: 'model',
      model_parameters: {},
      frameworks: ['STRIDE'],
      embeddings_model: 'embeddings',
      config_hash: 'a'.repeat(64),
      created_at: createdAt,
    },
    stage: {
      id: 'report_verifier',
      version: 1,
      hitlKind: null,
      usesModel: false,
    },
    checkpoint: {
      schema_version: 1,
      owner_id: ownerId,
      application_id: applicationId,
      run_id: selectedRunId,
      stage_id: 'report_verifier',
      stage_version: 1,
      attempt: 1,
      fencing_token: 1,
      idempotency_key: 'report-publication',
      trace_id: '0123456789abcdef0123456789abcdef',
      status: 'started',
      input_artifacts: [],
      output_artifacts: [],
      model_id: null,
      config_hash: 'a'.repeat(64),
      started_at: createdAt,
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
  };
}

async function withRunDirectory(
  run: (runDir: string) => Promise<void>,
): Promise<void> {
  const runDir = await mkdtemp('/tmp/threatforest-output-publisher-test-');
  try {
    await mkdir(join(runDir, 'source'));
    await mkdir(join(runDir, 'output'));
    await mkdir(join(runDir, 'state'));
    await writeFile(
      join(runDir, 'output', 'threatforest_data.json'),
      JSON.stringify({
        status: 'complete',
        threat_count: 3,
        high_severity_count: 2,
        categories: ['Spoofing', 'Tampering', 'Spoofing'],
      }),
    );
    await writeFile(
      join(runDir, 'output', 'threat_model_report.md'),
      '# Threat model\n',
    );
    await writeFile(
      join(runDir, 'state', 'scanner_context.json'),
      JSON.stringify({ project_name: 'Payments' }),
    );
    await writeQualityState(runDir);
    await run(runDir);
  } finally {
    await rm(runDir, { recursive: true, force: true });
  }
}

async function writeQualityState(runDir: string): Promise<void> {
  await mkdir(join(runDir, 'source', 'infra'), { recursive: true });
  await writeFile(join(runDir, 'source', 'infra', 'storage.ts'), 'The workload role has read access.\n');
  await writeFile(
    join(runDir, 'state', 'threats.json'),
    JSON.stringify({ threats: [{ id: 'THR-1' }] }),
  );
  await writeFile(
    join(runDir, 'state', 'attack_trees.json'),
    JSON.stringify({
      attack_trees: [
        {
          id: 'AT001',
          threat_id: 'THR-1',
          steps: [{ id: 'AT001-S1', parent_id: '' }, { id: 'AT001-S2', parent_id: 'AT001-S1' }],
        },
      ],
    }),
  );
  await writeFile(
    join(runDir, 'state', 'ttp_mappings.json'),
    JSON.stringify({
      ttp_mappings: [
        {
          attack_step_id: 'AT001-S1',
          technique_id: 'T1530',
          calibrated_confidence: 0.82,
          confidence_policy: 'similarity-margin-v1',
          accepted_precision_target: 0.7,
          abstained: false,
        },
        {
          attack_step_id: 'AT001-S2',
          calibrated_confidence: 0.62,
          confidence_policy: 'similarity-margin-v1',
          accepted_precision_target: 0.7,
          abstained: true,
          abstention_reason: 'Candidate confidence is below the acceptance target.',
        },
      ],
    }),
  );
  await writeFile(
    join(runDir, 'state', 'mitigations.json'),
    JSON.stringify({
      mitigations: [
        {
          attack_step_id: 'AT001-S1',
          technique_id: 'T1530',
          mitigation_text: 'Restrict object access.',
          evidence: [
            {
              source_type: 'repository',
              source_ref: 'infra/storage.ts',
              excerpt: 'The workload role has read access.',
              relevance: 'This is the authorization boundary.',
            },
          ],
        },
        {
          attack_step_id: 'AT001-S2',
          technique_id: '',
          mitigation_text: 'Monitor reads by the workload role.',
          evidence: [{
            source_type: 'repository',
            source_ref: 'infra/storage.ts',
            excerpt: 'The workload role has read access.',
            relevance: 'Unexpected reads can indicate exfiltration.',
          }],
        },
      ],
    }),
  );
}

function zipEntries(value: Uint8Array): Map<string, Uint8Array> {
  const buffer = Buffer.from(value);
  let end = -1;
  for (let index = buffer.length - 22; index >= 0; index -= 1) {
    if (buffer.readUInt32LE(index) === 0x06054b50) {
      end = index;
      break;
    }
  }
  assert.notEqual(end, -1);
  const count = buffer.readUInt16LE(end + 10);
  let central = buffer.readUInt32LE(end + 16);
  const entries = new Map<string, Uint8Array>();
  for (let index = 0; index < count; index += 1) {
    assert.equal(buffer.readUInt32LE(central), 0x02014b50);
    const size = buffer.readUInt32LE(central + 24);
    const nameLength = buffer.readUInt16LE(central + 28);
    const extraLength = buffer.readUInt16LE(central + 30);
    const commentLength = buffer.readUInt16LE(central + 32);
    const localOffset = buffer.readUInt32LE(central + 42);
    const name = buffer.toString(
      'utf8',
      central + 46,
      central + 46 + nameLength,
    );
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart =
      localOffset + 30 + localNameLength + localExtraLength;
    entries.set(name, buffer.subarray(dataStart, dataStart + size));
    central += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}
