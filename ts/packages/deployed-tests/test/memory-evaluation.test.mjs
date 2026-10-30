import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import {
  BedrockAgentCoreClient,
  GetBatchEvaluationCommand,
  StartBatchEvaluationCommand,
} from '@aws-sdk/client-bedrock-agentcore';
import {
  assertDeploymentAccount,
  awsJson,
  waitForLogEvents,
} from './support/aws-cli.mjs';
import { optional, required, skipUnless } from './support/env.mjs';

const BATCH_TERMINAL_STATUSES = new Set([
  'COMPLETED',
  'COMPLETED_WITH_ERRORS',
  'FAILED',
  'STOPPED',
]);

function batchEvaluationClient() {
  const profile = optional('TF_AWS_PROFILE');
  if (profile) process.env.AWS_PROFILE = profile;
  const region = required('TF_REGION');
  return new BedrockAgentCoreClient({ region });
}

function assertDeploymentKey(arn) {
  assert.ok(
    (arn || '').startsWith(`arn:aws:kms:${required('TF_REGION')}:${required('TF_ACCOUNT_ID')}:key/`),
    `Expected a KMS key in the deployed account and region; received ${arn}`,
  );
}

function applicationLogGroup(name) {
  return `/threatforest/${required('TF_ENVIRONMENT')}/${name}`;
}

test(
  'AgentCore Memory and Online Evaluation resources are deployed with encrypted logs',
  {
    skip: skipUnless(
      'TF_MEMORY_ID',
      'TF_EVALUATION_ARN',
      'TF_EVALUATION_LOG_GROUP',
      'TF_RUNTIME_LOG_GROUP',
    ),
  },
  () => {
    assertDeploymentAccount();
    assert.match(optional('TF_MEMORY_ID'), /^[A-Za-z0-9_-]+$/);
    assert.match(optional('TF_EVALUATION_ARN'), /^arn:aws:bedrock-agentcore:/);

    for (const name of [
      applicationLogGroup('memory'),
      applicationLogGroup('runtime'),
      'aws/spans',
      optional('TF_RUNTIME_LOG_GROUP'),
      optional('TF_EVALUATION_LOG_GROUP'),
      '/aws/bedrock-agentcore/evaluations/batch-evaluations/results/default',
    ]) {
      const groups = awsJson(
        'logs',
        'describe-log-groups',
        '--log-group-name-prefix',
        name,
      ).logGroups;
      const exact = groups.find((group) => group.logGroupName === name);
      assert.ok(exact, `Missing log group ${name}`);
      assertDeploymentKey(exact.kmsKeyId);
      assert.ok(Number(exact.retentionInDays) >= 365);
    }
  },
);

test(
  'completed run produces Memory and Evaluation telemetry',
  {
    timeout: 22 * 60_000,
    skip:
      skipUnless(
        'TF_TEST_RUN_ID',
        'TF_EVALUATION_LOG_GROUP',
      ) ||
      (optional('TF_REQUIRE_RUN_TELEMETRY') !== '1'
        ? 'Set TF_REQUIRE_RUN_TELEMETRY=1 after a completed run.'
        : false),
  },
  async () => {
    assertDeploymentAccount();
    const runId = optional('TF_TEST_RUN_ID');
    const evaluationSessionId = `tf-evaluation-${runId}`;
    const memoryEvents = await waitForLogEvents(
      applicationLogGroup('memory'),
      runId,
      {
        timeoutMs: 2 * 60_000,
        intervalMs: 10_000,
      },
    );
    const runtimeEvents = await waitForLogEvents(
      'aws/spans',
      [runId, 'threatforest.run.completed'],
      {
        timeoutMs: 2 * 60_000,
        intervalMs: 10_000,
      },
    );
    const projectionEvents = await waitForLogEvents(
      'aws/spans',
      [runId, 'threatforest.run.output_quality'],
      {
        timeoutMs: 2 * 60_000,
        intervalMs: 10_000,
      },
    );
    const evaluationEvents = await waitForLogEvents(
      optional('TF_EVALUATION_LOG_GROUP'),
      evaluationSessionId,
      {
        timeoutMs: 20 * 60_000,
        intervalMs: 15_000,
      },
    );
    assert.ok(memoryEvents.length > 0, `No Memory log events found for ${runId}`);
    assert.ok(
      runtimeEvents.some(({ message }) => {
        try {
          const span = JSON.parse(message);
          return (
            span.name === 'threatforest.run.completed' &&
            span.attributes?.['threatforest.run.completed'] === true &&
            span.attributes?.['session.id'] === runId
          );
        } catch {
          return false;
        }
      }),
      `No completed Runtime span found for ${runId}`,
    );
    assert.ok(
      projectionEvents.some(({ message }) => {
        try {
          const span = JSON.parse(message);
          return (
            span.name === 'threatforest.run.output_quality' &&
            span.attributes?.['threatforest.evaluation.ready'] === true &&
            span.attributes?.['session.id'] === evaluationSessionId &&
            span.attributes?.['threatforest.evaluation.session_id'] ===
              evaluationSessionId
          );
        } catch {
          return false;
        }
      }),
      `No bounded output-quality projection found for ${evaluationSessionId}`,
    );
    const memoryReuseRunId = optional('TF_MEMORY_REUSE_RUN_ID');
    if (memoryReuseRunId !== null) {
      const retrievalEvents = await waitForLogEvents(
        'aws/spans',
        [memoryReuseRunId, 'RetrieveMemoryRecords'],
        {
          timeoutMs: 2 * 60_000,
          intervalMs: 10_000,
        },
      );
      assert.ok(
        retrievalEvents.some(({ message }) => {
          try {
            const span = JSON.parse(message);
            return (
              span.name === 'BedrockAgentCore.RetrieveMemoryRecords' &&
              span.attributes?.['session.id'] === memoryReuseRunId
            );
          } catch {
            return false;
          }
        }),
        `No AgentCore Memory retrieval span found for ${memoryReuseRunId}`,
      );
    }
    const results = evaluationEvents.flatMap(({ message }) => {
      try {
        const result = JSON.parse(message);
        return result.name === 'gen_ai.evaluation.result' &&
          result.attributes?.['session.id'] === evaluationSessionId
          ? [result]
          : [];
      } catch {
        return [];
      }
    });
    const byName = new Map(
      results.map((result) => [
        result.attributes?.['gen_ai.evaluation.name'],
        result,
      ]),
    );
    assert.ok(
      byName.has('Builtin.ResponseRelevance'),
      `No Response Relevance result found for ${evaluationSessionId}`,
    );
    assert.equal(
      byName
        .get('ThreatForestDomainQuality')
        ?.attributes?.['gen_ai.evaluation.score.label'],
      'Pass',
      `ThreatForest domain-quality evaluation did not pass for ${evaluationSessionId}`,
    );
  },
);

test(
  'AgentCore batch evaluation can use the telemetry customer KMS key',
  {
    timeout: 25 * 60_000,
    skip:
      skipUnless('TF_EVALUATION_ARN', 'TF_EVALUATION_LOG_GROUP') ||
      (optional('TF_RUN_BATCH_EVALUATION_TEST') !== '1'
        ? 'Set TF_RUN_BATCH_EVALUATION_TEST=1 after Online Evaluation succeeds.'
        : false),
  },
  async () => {
    assertDeploymentAccount();
    const evaluationLogGroup = optional('TF_EVALUATION_LOG_GROUP');
    const groups = awsJson(
      'logs',
      'describe-log-groups',
      '--log-group-name-prefix',
      evaluationLogGroup,
    ).logGroups;
    const exact = groups.find(
      (group) => group.logGroupName === evaluationLogGroup,
    );
    assert.ok(exact, `Missing log group ${evaluationLogGroup}`);
    assertDeploymentKey(exact.kmsKeyId);

    const client = batchEvaluationClient();
    let batchEvaluationId = optional('TF_BATCH_EVALUATION_ID');
    if (batchEvaluationId === null) {
      const endTime = new Date();
      const started = await client.send(
        new StartBatchEvaluationCommand({
          batchEvaluationName: `ThreatForestKmsAcceptance${Date.now()}`,
          clientToken: randomUUID(),
          description:
            'KMS data-plane acceptance for bounded ThreatForest evaluation projections',
          dataSourceConfig: {
            onlineEvaluationConfigSource: {
              onlineEvaluationConfigArn: optional('TF_EVALUATION_ARN'),
              timeRange: {
                startTime: new Date(endTime.getTime() - 2 * 60 * 60_000),
                endTime,
              },
            },
          },
          kmsKeyArn: exact.kmsKeyId,
          tags: {
            Application: 'ThreatForest',
            Environment: 'test',
            Purpose: 'kms-acceptance',
          },
        }),
      );
      batchEvaluationId = started.batchEvaluationId;
      assert.ok(batchEvaluationId);
      assert.equal(started.kmsKeyArn, exact.kmsKeyId);
      console.log(`Started KMS batch evaluation ${batchEvaluationId}`);
    }

    const deadline = Date.now() + 20 * 60_000;
    let current;
    do {
      current = await client.send(
        new GetBatchEvaluationCommand({ batchEvaluationId }),
      );
      if (BATCH_TERMINAL_STATUSES.has(current.status)) break;
      await delay(15_000);
    } while (Date.now() < deadline);

    assert.ok(current, `No batch evaluation response for ${batchEvaluationId}`);
    assert.equal(current.kmsKeyArn, exact.kmsKeyId);
    assert.equal(
      current.status,
      'COMPLETED',
      `Batch evaluation ${batchEvaluationId} ended with ${current.status}: ${
        current.errorDetails?.join('; ') || 'no error details'
      }`,
    );
    assert.ok(
      Number(current.evaluationResults?.numberOfSessionsCompleted) >= 1,
      `Batch evaluation ${batchEvaluationId} completed no sessions`,
    );
    assert.equal(
      Number(current.evaluationResults?.numberOfSessionsFailed || 0),
      0,
    );
    const batchLogGroupName =
      current.outputConfig?.cloudWatchConfig?.logGroupName;
    assert.ok(batchLogGroupName);
    const batchGroups = awsJson(
      'logs',
      'describe-log-groups',
      '--log-group-name-prefix',
      batchLogGroupName,
    ).logGroups;
    const batchGroup = batchGroups.find(
      (group) => group.logGroupName === batchLogGroupName,
    );
    assert.ok(batchGroup, `Missing batch result log group ${batchLogGroupName}`);
    assert.equal(batchGroup.kmsKeyId, exact.kmsKeyId);
    assert.ok(Number(batchGroup.retentionInDays) >= 365);
  },
);
