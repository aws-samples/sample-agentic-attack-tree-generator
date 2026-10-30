import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { Agent } from '@strands-agents/sdk';
import { createRunEngineConfig } from '../config.js';
import { MlServiceClient } from '../ml-client.js';
import { runParallelPipeline } from './parallel.js';

const engineConfig = createRunEngineConfig({
  provider: 'AWS Bedrock', modelId: 'test-model', embeddingsModel: 'test-embedding', parallelMaxRetries: 0,
});

function tree(threatId: string) {
  return {
    id: 'AT001', threat_id: threatId,
    steps: [{ id: 'AT001-S1', description: 'Read workload objects', parent_id: '' }],
  };
}

function mitigation(text: string, techniqueId: string) {
  return {
    attack_step_id: 'AT001-S1', technique_id: techniqueId, mitigation_text: text,
    implementation_guidance: 'Restrict the specific role in the bucket policy.',
    remediation_type: 'quick_win', priority: 1, also_applies_to: [],
    evidence: [{ source_type: 'repository', source_ref: 'infra.ts',
      excerpt: 'bucket.grantRead(workload);', relevance: 'The role can read objects.' }],
  };
}

test('parallel pipeline invokes mitigation generation for all-abstained steps', async (t) => {
  const root = mkdtempSync('/tmp/threatforest-abstention-pipeline-');
  const run = join(root, 'run');
  const state = join(run, 'state');
  mkdirSync(state, { recursive: true });
  try {
    writeFileSync(join(root, 'infra.ts'), 'bucket.grantRead(workload);\n');
    writeFileSync(join(state, 'threats.json'), JSON.stringify({ threats: [{ id: 'THR-1' }] }));
    writeFileSync(join(state, 'scanner_context.json'), '{}');
    writeFileSync(join(state, 't0_attack_trees.json'), JSON.stringify({ attack_trees: [tree('THR-1')] }));
    t.mock.method(MlServiceClient.prototype, 'matchSteps', async () => []);
    let invocations = 0;
    t.mock.method(Agent.prototype, 'invoke', async () => {
      invocations++;
      const input = JSON.parse(readFileSync(join(state, 't0_mitigations_input.json'), 'utf8'));
      assert.equal(input.ttp_mappings[0].abstained, true);
      writeFileSync(join(state, 't0_mitigations.json'), JSON.stringify({
        mitigations: [mitigation('Restrict the workload role.', '')],
      }));
      return {} as Awaited<ReturnType<Agent['invoke']>>;
    });
    await runParallelPipeline(root, run, ['attack'], null, engineConfig);
    assert.equal(invocations, 1);
    const result = JSON.parse(readFileSync(join(state, 'mitigations.json'), 'utf8'));
    assert.equal(result.mitigations.length, 1);
    assert.equal(result.mitigations[0].technique_id, '');
    assert.equal(JSON.parse(readFileSync(join(state, 'ttp_mappings.json'), 'utf8')).ttp_mappings[0].abstained, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('parallel merge retains separate component controls for the same technique', async (t) => {
  const root = mkdtempSync('/tmp/threatforest-control-scope-');
  const run = join(root, 'run');
  const state = join(run, 'state');
  mkdirSync(state, { recursive: true });
  try {
    writeFileSync(join(root, 'infra.ts'), 'bucket.grantRead(workload);\n');
    writeFileSync(join(state, 'scanner_context.json'), '{}');
    writeFileSync(join(state, 'threats.json'), JSON.stringify({ threats: [{ id: 'THR-1' }, { id: 'THR-2' }] }));
    for (let i = 0; i < 2; i++) {
      writeFileSync(join(state, `t${i}_attack_trees.json`), JSON.stringify({ attack_trees: [tree(`THR-${i + 1}`)] }));
      writeFileSync(join(state, `t${i}_mitigations.json`), JSON.stringify({
        mitigations: [mitigation(`Restrict component ${i + 1}.`, 'T1530')],
      }));
    }
    t.mock.method(MlServiceClient.prototype, 'matchSteps', async (steps: string[]) =>
      steps.map((attack_step) => ({ attack_step, matches: [{
        technique_id: 'T1530', name: 'Data from cloud storage', description: 'Read objects',
        kill_chain_phases: [], similarity: 0.95, confidence: 'high' as const, framework: 'attack' as const,
      }] })),
    );
    await runParallelPipeline(root, run, ['attack'], null, engineConfig);
    const result = JSON.parse(readFileSync(join(state, 'mitigations.json'), 'utf8')).mitigations;
    assert.equal(result.length, 2);
    assert.deepEqual(result.map((item: Record<string, unknown>) => item['attack_step_id']), ['AT001-S1', 'AT002-S1']);
    assert.deepEqual(result.map((item: Record<string, unknown>) => item['also_applies_to']), [[], []]);
    assert.deepEqual(result.map((item: Record<string, unknown>) => item['mitigation_text']), ['Restrict component 1.', 'Restrict component 2.']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
