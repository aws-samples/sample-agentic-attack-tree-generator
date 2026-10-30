import assert from 'node:assert/strict';
import { chmod, writeFile } from 'node:fs/promises';
import test from 'node:test';
import {
  apiRequest,
  createApplication,
  deleteApplication,
  expectApi,
  poll,
  uploadBuffer,
} from './support/api.mjs';
import { agentEnabled, optional } from './support/env.mjs';

const FIXTURE = `# Deployed ThreatForest Fixture

The service exposes an authenticated HTTPS API through Amazon API Gateway.
Workloads run on AWS Lambda and Amazon ECS. Data is stored in Amazon S3 and
Amazon DynamoDB with AWS KMS encryption. Amazon Cognito authenticates users.

An attacker who steals a user token may enumerate applications, read uploaded
design documents, or attempt to invoke the threat-model workflow as that user.
`;

function shellValue(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

async function writeFixtureHandoff(values) {
  const path =
    optional('TF_AGENT_FIXTURE_ENV_FILE') ||
    '/tmp/threatforest-agent-hitl-fixture.env';
  const content =
    '# Generated deployed HITL fixture identifiers. Delete after testing.\n' +
    Object.entries(values)
      .map(([name, value]) => `${name}=${shellValue(value)}`)
      .join('\n') +
    '\n';
  await writeFile(path, content, { encoding: 'utf8', mode: 0o600 });
  await chmod(path, 0o600);
  console.log(`Wrote deployed HITL fixture identifiers to ${path}`);
}

async function runToCompletion(token, applicationId, artifactId, options = {}) {
  const { body: created } = await expectApi('/api/runs', token, {
    method: 'POST',
    json: {
      app_id: applicationId,
      project_path: '',
      threat_source: 'auto',
      threat_file_path: null,
      frameworks: ['attack', 'atlas', 'wiz'],
      skip_nodes: [],
      source_artifact_ids: [artifactId],
    },
  });
  const runId = created.run_id;
  const resolvedKinds = [];
  const terminal = await poll(
    async () => {
      const { body: run } = await expectApi(
        `/api/runs/${encodeURIComponent(runId)}`,
        token,
      );
      if (run.status === 'failed') {
        throw new Error(`Agent run ${runId} failed: ${run.error || 'unknown error'}`);
      }
      if (run.status === 'complete') return run;
      const { body: pending } = await expectApi(
        `/api/runs/${encodeURIComponent(runId)}/interactions`,
        token,
      );
      for (const interaction of pending.interactions || []) {
        const submit =
          resolvedKinds.length === 0 && options.submitFirst !== false;
        const action = submit ? 'respond' : 'skip';
        const response = await apiRequest(
          `/api/runs/${encodeURIComponent(runId)}/interactions/${encodeURIComponent(
            interaction.interaction_id,
          )}/${action}`,
          token,
          {
            method: 'POST',
            json: {
              revision: interaction.revision,
              ...(submit
                ? {
                    text: JSON.stringify({
                      action: 'proceed',
                      confirmed_only: true,
                      feedback: 'Approved by deployed interaction test.',
                    }),
                  }
                : {}),
            },
          },
        );
        if (!response.response.ok) {
          throw new Error(
            `HITL ${action} failed: ${response.response.status} ${JSON.stringify(response.body)}`,
          );
        }
        resolvedKinds.push(interaction.kind);
      }
      return null;
    },
    {
      timeoutMs: 2 * 60 * 60_000,
      intervalMs: 10_000,
      label: 'AgentCore run completion',
    },
  );
  assert.equal(terminal.status, 'complete');
  assert.deepEqual(
    [...resolvedKinds].sort(),
    ['interviewer', 'scanner_review', 'threat_review'],
    'Expected every durable HITL boundary exactly once.',
  );
  return { runId, interactionCount: resolvedKinds.length };
}

test(
  'agent workflow uploads evidence, crosses HITL boundaries, publishes report, and can reuse memory',
  {
    skip:
      agentEnabled && optional('TF_TEST_USER_A_ACCESS_TOKEN') && optional('TF_BASE_URL')
        ? false
        : 'Set TF_RUN_DEPLOYED_TESTS=1, TF_RUN_AGENT_HITL_TEST=1, TF_BASE_URL, and a user A access token.',
    timeout: 2 * 60 * 60_000,
  },
  async () => {
    const token = optional('TF_TEST_USER_A_ACCESS_TOKEN');
    const application = await createApplication(token, 'Agent HITL Test');
    let fixturePreserved = false;
    try {
      const upload = await uploadBuffer(
        token,
        application.id,
        'architecture.md',
        'text/markdown',
        FIXTURE,
      );
      assert.equal(upload.manifest.status, 'ready');
      const artifactId = upload.manifest.source_artifact?.artifact_id;
      assert.ok(artifactId);

      const completed = await runToCompletion(token, application.id, artifactId);
      const versions = await poll(
        async () => {
          const { body } = await expectApi(
            `/api/applications/${encodeURIComponent(application.id)}/versions`,
            token,
          );
          return body.versions?.length > 0 ? body.versions : null;
        },
        { timeoutMs: 10 * 60_000, intervalMs: 5_000, label: 'published version' },
      );
      const version = versions.find(
        (entry) => entry.run_id === completed.runId || entry.status === 'completed',
      );
      assert.ok(version);

      const { body: data } = await expectApi(
        `/api/applications/${encodeURIComponent(
          application.id,
        )}/versions/${encodeURIComponent(version.id)}/data`,
        token,
      );
      const threats = Array.isArray(data.threats) ? data.threats : [];
      const attackTrees = Array.isArray(data.attack_trees)
        ? data.attack_trees
        : [];
      const mappings = attackTrees.flatMap((tree) =>
        Array.isArray(tree.ttc_mappings) ? tree.ttc_mappings : [],
      );
      const mitigations = attackTrees.flatMap((tree) =>
        Array.isArray(tree.mitigations) ? tree.mitigations : [],
      );
      assert.ok(threats.length > 0, 'Published report contains no threats.');
      assert.equal(data.threat_count, threats.length);
      assert.ok(
        attackTrees.length > 0 &&
          attackTrees.every(
            (tree) =>
              typeof tree.mermaid_code === 'string' &&
              tree.mermaid_code.trim().length > 0,
          ),
        'Published report must contain rendered attack trees.',
      );
      assert.ok(mappings.length > 0, 'Published report contains no accepted TTP mappings.');
      assert.equal(data.mapping_summary?.total_mappings, mappings.length);
      assert.ok(
        mappings.every(
          (mapping) =>
            typeof mapping.technique_id === 'string' &&
            mapping.technique_id.trim().length > 0 &&
            Number.isFinite(mapping.confidence) &&
            mapping.confidence >= 0.7,
        ),
        'Every published TTP mapping must satisfy the acceptance threshold.',
      );
      assert.ok(mitigations.length > 0, 'Published report contains no mitigations.');
      assert.ok(
        mitigations.every(
          (mitigation) =>
            typeof mitigation.description === 'string' &&
            mitigation.description.trim().length > 0 &&
            Array.isArray(mitigation.evidence) &&
            mitigation.evidence.length > 0,
        ),
        'Every published mitigation must contain a description and evidence.',
      );

      const report = await expectApi(
        `/api/applications/${encodeURIComponent(
          application.id,
        )}/versions/${encodeURIComponent(version.id)}/report/metadata`,
        token,
      );
      assert.equal(report.body.report?.run_id, completed.runId);
      assert.match(report.body.report?.sha256 || '', /^[a-f0-9]{64}$/);
      assert.ok(
        Number.isSafeInteger(report.body.report?.size_bytes) &&
          report.body.report.size_bytes > 0,
      );

      const download = await apiRequest(
        `/api/applications/${encodeURIComponent(
          application.id,
        )}/versions/${encodeURIComponent(version.id)}/report`,
        token,
      );
      assert.equal(download.response.status, 302);
      const location = download.response.headers.get('location');
      assert.ok(location);
      const artifact = await fetch(location, { redirect: 'manual' });
      assert.equal(artifact.status, 200);
      assert.equal(artifact.headers.get('content-type'), 'application/zip');
      assert.match(
        artifact.headers.get('content-disposition') || '',
        /\.tfreport/,
      );
      const archive = Buffer.from(await artifact.arrayBuffer());
      assert.equal(archive.byteLength, report.body.report.size_bytes);
      assert.equal(archive.subarray(0, 2).toString('ascii'), 'PK');

      let memoryReuseRunId = null;
      if (optional('TF_RUN_MEMORY_REUSE_TEST') === '1') {
        const second = await runToCompletion(token, application.id, artifactId, {
          submitFirst: false,
        });
        assert.notEqual(second.runId, completed.runId);
        memoryReuseRunId = second.runId;
      }
      if (optional('TF_PRESERVE_AGENT_FIXTURE') === '1') {
        await writeFixtureHandoff({
          TF_TEST_RUN_ID: completed.runId,
          ...(memoryReuseRunId === null
            ? {}
            : { TF_MEMORY_REUSE_RUN_ID: memoryReuseRunId }),
          TF_TEST_APPLICATION_ID: application.id,
          TF_TEST_UPLOAD_ID: upload.uploadId,
          TF_TEST_ARTIFACT_KEY: upload.objectKey,
          TF_MCP_TEST_APPLICATION_ID: application.id,
          TF_MCP_TEST_SOURCE_ARTIFACT_IDS: artifactId,
        });
        fixturePreserved = true;
      }
    } finally {
      if (!fixturePreserved) {
        await deleteApplication(token, application.id);
      }
    }
  },
);
