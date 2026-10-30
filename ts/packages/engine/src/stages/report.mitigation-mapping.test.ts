import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runReportGenerator } from './report.js';

test('report embeds every applicable mitigation on its attack step', async () => {
  const runDir = mkdtempSync(join(tmpdir(), 'tf-report-mitigations-'));
  const stateDir = join(runDir, 'state');
  mkdirSync(stateDir, { recursive: true });
  const write = (name: string, value: unknown) =>
    writeFileSync(join(stateDir, name), JSON.stringify(value), 'utf8');

  write('scanner_context.json', {});
  write('threats.json', {
    threats: [
      {
        id: 'T001',
        title: 'Object data disclosure',
        description: 'An actor can read private objects.',
      },
    ],
  });
  write('attack_trees.json', {
    attack_trees: [
      {
        threat_id: 'T001',
        root_goal: 'Read private data',
        steps: [
          {
            id: 'AT001-S1',
            title: 'Read object',
            description: 'Read a private object.',
            category: 'attack',
          },
          {
            id: 'AT001-S2',
            title: 'Exfiltrate object',
            description: 'Exfiltrate the object.',
            category: 'attack',
          },
        ],
      },
    ],
  });
  write('ttp_mappings.json', {
    ttp_mappings: [
      {
        attack_step_id: 'AT001-S1',
        technique_id: 'T1530',
        technique_name: 'Data from Cloud Storage',
        similarity_score: 0.82,
      },
    ],
  });
  write('mitigations.json', {
    mitigations: [
      {
        attack_step_id: 'AT001-S1',
        technique_id: 'T1530',
        mitigation_text: 'Restrict object access.',
        implementation_guidance: 'Use workload-scoped IAM.',
        priority: 1,
        evidence: [],
        also_applies_to: [],
      },
      {
        attack_step_id: 'AT001-S1',
        technique_id: 'T1530',
        mitigation_text: 'Alert on anomalous reads.',
        implementation_guidance: 'Create a detection for unusual object reads.',
        priority: 2,
        evidence: [],
        also_applies_to: ['AT001-S2'],
      },
    ],
  });

  await runReportGenerator('/workspace/example', runDir);

  const data = JSON.parse(
    readFileSync(join(runDir, 'output', 'threatforest_data.json'), 'utf8'),
  );
  const tree = data.attack_trees[0];
  assert.equal(tree.attack_steps[0].mitigations.length, 2);
  assert.equal(tree.attack_steps[1].mitigations.length, 1);
  assert.equal(tree.mitigations.length, 3);
  assert.equal(tree.attack_steps[0].ttp_mappings[0].node_id, 'S0');
  assert.equal(
    tree.attack_steps[0].ttp_mappings[0].attack_step_id,
    'AT001-S1',
  );
  assert.equal(tree.attack_steps[0].mitigations[0].attack_step, 'S0');
  assert.equal(tree.attack_steps[0].mitigations[0].attack_step_id, 'AT001-S1');
});
