import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createModel,
  traceAttrs,
  type RunGraphOptions,
} from '@threatforest/engine';
import type { StageExecutionContext } from '../src/contracts.js';
import { EngineGraphStageExecutor } from '../src/engine-adapter.js';

interface CapturedRun {
  model: Record<string, unknown>;
  options: RunGraphOptions;
  trace: ReturnType<typeof traceAttrs>;
}

test('two hosted runs construct their selected models without cross-run config leakage', async () => {
  const captured = new Map<string, CapturedRun>();
  const memoryQueries: Array<Record<string, unknown>> = [];
  const adapter = new EngineGraphStageExecutor({
    workspaceResolver: {
      async resolve(context) {
        return {
          repoPath: `/tmp/${context.run.run_id}/source`,
          runDir: `/tmp/${context.run.run_id}`,
        };
      },
    },
    memory: {
      async recordApprovedFeedback() {},
      async recordThreatModel() {},
      async retrieveApplicationContext(input) {
        memoryQueries.push({ ...input });
        return [`prior-context-for-${input.applicationId}`];
      },
    },
    graphRunner: async (_repoPath, options) => {
      assert.notEqual(options, undefined);
      assert.notEqual(options!.engineConfig, undefined);
      const model = (await createModel(options!.engineConfig!)) as unknown as {
        getConfig(): Record<string, unknown>;
      };
      captured.set(model.getConfig().modelId as string, {
        model: model.getConfig(),
        options: options!,
        trace: traceAttrs('scanner'),
      });
      assert.equal(options!.throwOnNodeFailure, true);
      options!.onNodeEvent?.({ phase: 'complete', nodeId: 'scanner' });
      return {
        status: 'interrupted',
        output_dir: '/tmp/output',
        completed_nodes: ['scanner'],
      };
    },
  });

  await Promise.all([
    adapter.execute(
      contextFor('run-a', 'global.anthropic.claude-sonnet-4-6', {
        temperature: 0.1,
        max_tokens: 1111,
      }, 'embedding-a'),
    ),
    adapter.execute(
      contextFor('run-b', 'global.amazon.nova-2-lite-v1:0', {
        temperature: 0.9,
        maxTokens: 2222,
      }, 'embedding-b'),
    ),
  ]);

  const first = captured.get('global.anthropic.claude-sonnet-4-6');
  const second = captured.get('global.amazon.nova-2-lite-v1:0');
  assert.notEqual(first, undefined);
  assert.notEqual(second, undefined);
  assert.equal(first!.model.temperature, 0.1);
  assert.equal(first!.model.maxTokens, 1111);
  assert.equal(second!.model.temperature, 0.9);
  assert.equal(second!.model.maxTokens, 2222);
  assert.equal(first!.options.engineConfig!.embeddingsModel, 'embedding-a');
  assert.equal(second!.options.engineConfig!.embeddingsModel, 'embedding-b');
  assert.equal(first!.options.engineConfig!.provider, 'AWS Bedrock');
  assert.equal(first!.options.engineConfig!.modelId, 'global.anthropic.claude-sonnet-4-6');
  assert.equal(first!.options.engineConfig!.awsRegion, 'eu-west-2');
  assert.equal(first!.options.businessContext?.description, 'Business context for run-a');
  assert.equal(second!.options.businessContext?.description, 'Business context for run-b');
  assert.deepEqual(first!.options.engineConfig!.modelParameters, {
    temperature: 0.1,
    max_tokens: 1111,
  });
  assert.deepEqual(first!.options.engineConfig!.bedrock, {
    temperature: 0.1,
    max_tokens: 1111,
    model_id: 'global.anthropic.claude-sonnet-4-6',
  });
  assert.deepEqual(second!.options.engineConfig!.bedrock, {
    temperature: 0.9,
    maxTokens: 2222,
    model_id: 'global.amazon.nova-2-lite-v1:0',
  });
  assert.notEqual(first!.options.engineConfig, second!.options.engineConfig);
  assert.equal(first!.trace['threatforest.run.id'], 'run-a');
  assert.equal(second!.trace['threatforest.run.id'], 'run-b');
  assert.equal(first!.trace['threatforest.owner.id'], 'usr_owner');
  assert.equal(first!.trace['threatforest.stage.id'], 'scanner');
  assert.equal(first!.trace['threatforest.stage.attempt'], 1);
  assert.deepEqual(first!.options.historicalContext, [
    'prior-context-for-app_application',
  ]);
  assert.deepEqual(second!.options.historicalContext, [
    'prior-context-for-app_application',
  ]);
  assert.equal(memoryQueries.length, 2);
  assert.equal(memoryQueries[0]?.['actorId'], 'actor');
});

test('captured graph node failures preserve durable HITL boundaries', async () => {
  const adapter = new EngineGraphStageExecutor({
    workspaceResolver: {
      async resolve() {
        return {
          repoPath: '/tmp/hitl/source',
          runDir: '/tmp/hitl',
        };
      },
    },
    graphRunner: async (_repoPath, options) => {
      assert.equal(options?.throwOnNodeFailure, true);
      try {
        await options!.interactionFn!([
          {
            id: 'scanner-review',
            reason: {
              phase: 'scanner_review',
              message: 'Confirm scanner output',
            },
          },
        ]);
      } catch (error) {
        if (options?.throwOnNodeFailure) {
          throw error;
        }
      }
      return {
        status: 'failed',
        output_dir: '/tmp/hitl/output',
        completed_nodes: [],
        error: 'scanner_review failed',
      };
    },
  });
  const context = contextFor(
    'run-hitl-boundary',
    'global.amazon.nova-2-lite-v1:0',
    {},
    'embedding',
  );
  context.run.current_stage_id = 'scanner_review';
  context.stage = {
    id: 'scanner_review',
    version: 1,
    hitlKind: 'scanner_review',
    usesModel: false,
  };

  const result = await adapter.execute(context);

  assert.equal(result.status, 'awaiting_input');
  if (result.status !== 'awaiting_input') {
    assert.fail('expected a durable HITL boundary');
  }
  assert.deepEqual(result.reason, {
    phase: 'scanner_review',
    message: 'Confirm scanner output',
  });
  assert.deepEqual(result.transcript, {
    schema_version: 1,
    interrupts: [
      {
        id: 'scanner-review',
        reason: {
          phase: 'scanner_review',
          message: 'Confirm scanner output',
        },
      },
    ],
  });
});

test('target completion aborts the graph before a downstream stage can run', async () => {
  let boundarySignal: AbortSignal | undefined;
  const adapter = new EngineGraphStageExecutor({
    workspaceResolver: {
      async resolve() {
        return {
          repoPath: '/tmp/stage-boundary/source',
          runDir: '/tmp/stage-boundary',
        };
      },
    },
    graphRunner: async (_repoPath, options) => {
      boundarySignal = options?.cancelSignal;
      assert.equal(boundarySignal?.aborted, false);
      options?.onNodeEvent?.({ phase: 'complete', nodeId: 'scanner' });
      assert.equal(boundarySignal?.aborted, true);
      return {
        status: 'interrupted',
        output_dir: '/tmp/stage-boundary/output',
        completed_nodes: ['scanner'],
      };
    },
  });

  const result = await adapter.execute(
    contextFor(
      'run-stage-boundary',
      'global.amazon.nova-2-lite-v1:0',
      {},
      'embedding',
    ),
  );

  assert.equal(result.status, 'completed');
  assert.equal(boundarySignal?.aborted, true);
});

test('external graph cancellation preserves the runtime shutdown reason', async () => {
  const shutdown = new Error('runtime shutdown');
  shutdown.name = 'AbortError';
  const controller = new AbortController();
  controller.abort(shutdown);
  const adapter = new EngineGraphStageExecutor({
    workspaceResolver: {
      async resolve() {
        return {
          repoPath: '/tmp/runtime-shutdown/source',
          runDir: '/tmp/runtime-shutdown',
        };
      },
    },
    graphRunner: async (_repoPath, options) => {
      assert.equal(options?.cancelSignal?.aborted, true);
      return {
        status: 'interrupted',
        output_dir: '/tmp/runtime-shutdown/output',
        completed_nodes: [],
      };
    },
  });
  const context = contextFor(
    'run-runtime-shutdown',
    'global.amazon.nova-2-lite-v1:0',
    {},
    'embedding',
  );
  context.signal = controller.signal;

  await assert.rejects(adapter.execute(context), (error) => error === shutdown);
});

test('selected provider credentials merge only after safe generation parameters are validated', async () => {
  let captured: RunGraphOptions | undefined;
  const adapter = new EngineGraphStageExecutor({
    workspaceResolver: {
      async resolve() {
        return { repoPath: '/tmp/openai/source', runDir: '/tmp/openai' };
      },
    },
    modelCredentials: {
      async resolve(ownerId, provider) {
        assert.equal(ownerId, 'usr_owner');
        assert.equal(provider, 'OpenAI');
        return { apiKey: 'managed-key' };
      },
    },
    graphRunner: async (_repoPath, options) => {
      captured = options;
      options?.onNodeEvent?.({ phase: 'complete', nodeId: 'scanner' });
      return {
        status: 'interrupted',
        output_dir: '/tmp/output',
        completed_nodes: ['scanner'],
      };
    },
  });

  await adapter.execute(
    contextFor(
      'run-openai',
      'gpt-5.4',
      { temperature: 0.2, maxTokens: 4096 },
      'embedding-openai',
      'OpenAI',
    ),
  );

  assert.equal(captured?.engineConfig?.openai['apiKey'], 'managed-key');
  assert.equal(captured?.engineConfig?.openai['temperature'], 0.2);
  assert.equal(captured?.engineConfig?.openai['maxTokens'], 4096);
  assert.deepEqual(captured?.engineConfig?.bedrock, {});
});

test('unsafe provider and transport parameters are rejected before managed credentials are resolved', async () => {
  const unsafeKeys = [
    'endpoint',
    'baseURL',
    'proxy',
    'headers',
    'auth',
    'transport',
    'apiKey',
  ];
  for (const unsafeKey of unsafeKeys) {
    let credentialResolutions = 0;
    let graphRuns = 0;
    const adapter = new EngineGraphStageExecutor({
      workspaceResolver: {
        async resolve() {
          return { repoPath: '/tmp/rejected/source' };
        },
      },
      modelCredentials: {
        async resolve() {
          credentialResolutions += 1;
          return { apiKey: 'must-not-be-loaded' };
        },
      },
      graphRunner: async () => {
        graphRuns += 1;
        return {
          status: 'success',
          output_dir: '/tmp/output',
          completed_nodes: [],
        };
      },
    });

    await assert.rejects(
      adapter.execute(
        contextFor(
          `run-rejected-${unsafeKey}`,
          'gpt-5.4',
          { [unsafeKey]: 'https://attacker.invalid' },
          'embedding-openai',
          'OpenAI',
        ),
      ),
      new RegExp(`Unsupported hosted model parameter "${unsafeKey}"`),
    );
    assert.equal(credentialResolutions, 0);
    assert.equal(graphRuns, 0);
  }
});

test('a successful graph cannot complete or publish without target-node completion proof', async () => {
  let publications = 0;
  const adapter = new EngineGraphStageExecutor({
    workspaceResolver: {
      async resolve() {
        return {
          repoPath: '/tmp/report/source',
          runDir: '/tmp/report',
        };
      },
    },
    outputPublisher: {
      async publish() {
        publications += 1;
        return [];
      },
    },
    graphRunner: async () => ({
      status: 'success',
      output_dir: '/tmp/report/output',
      completed_nodes: [],
    }),
  });
  const context = contextFor(
    'run-incomplete-report',
    'global.amazon.nova-2-lite-v1:0',
    {},
    'embedding',
  );
  context.run.current_stage_id = 'report_verifier';
  context.stage = {
    id: 'report_verifier',
    version: 1,
    hitlKind: null,
    usesModel: false,
  };

  await assert.rejects(
    adapter.execute(context),
    /engine stopped before stage report_verifier completed/,
  );
  assert.equal(publications, 0);
});

function contextFor(
  runId: string,
  modelId: string,
  modelParameters: Record<string, string | number | boolean>,
  embeddingsModel: string,
  provider = 'AWS Bedrock',
): StageExecutionContext {
  return {
    scope: {
      owner_id: 'usr_owner',
      application_id: 'app_application',
    },
    run: {
      schema_version: 1,
      owner_id: 'usr_owner',
      application_id: 'app_application',
      run_id: runId,
      status: 'running',
      source_artifact_ids: [],
      threat_artifact_id: null,
      current_stage_id: 'scanner',
      trace_id: `trace-${runId}`,
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
      owner_id: 'usr_owner',
      application_id: 'app_application',
      run_id: runId,
      provider,
      model_id: modelId,
      aws_region: 'eu-west-2',
      model_parameters: modelParameters,
      frameworks: ['attack'],
      embeddings_model: embeddingsModel,
      business_context: {
        description: `Business context for ${runId}`,
        regulatory_frameworks: ['PCI DSS'],
        data_sensitivity: 'regulated_financial',
        cia_priority: ['availability', 'integrity', 'confidentiality'],
      },
      config_hash: 'a'.repeat(64),
      created_at: '2026-08-19T12:00:00.000Z',
    },
    stage: { id: 'scanner', version: 1, hitlKind: null, usesModel: true },
    checkpoint: {
      schema_version: 1,
      owner_id: 'usr_owner',
      application_id: 'app_application',
      run_id: runId,
      stage_id: 'scanner',
      stage_version: 1,
      status: 'started',
      revision: 1,
      attempt: 1,
      idempotency_key: `key-${runId}`,
      lease_fencing_token: 1,
      output_artifacts: [],
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
