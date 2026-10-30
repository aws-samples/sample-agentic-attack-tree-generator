import assert from 'node:assert/strict';
import test from 'node:test';
import { ThreatForestDataSchema } from './ui-graph.js';

test('UI graph schema preserves direct attack-step mitigation associations', () => {
  const parsed = ThreatForestDataSchema.parse({
    attack_trees: [
      {
        threat_id: 'T001',
        threat_statement: 'Object data can be read.',
        threat_category: 'Information Disclosure',
        mermaid_code: 'graph TD\nS0["Read object"]',
        attack_steps: [
          {
            node_id: 'S0',
            label: 'Read object',
            ttp_mappings: [
              {
                attack_step: 'Read object',
                attack_step_id: 'AT001-S1',
                node_id: 'S0',
                technique_id: 'T1530',
                technique_name: 'Data from Cloud Storage',
                confidence: 0.82,
              },
            ],
            mitigations: [
              {
                name: 'Restrict object access',
                attack_step: 'S0',
                attack_step_id: 'AT001-S1',
              },
            ],
          },
        ],
        mitigations: [
          {
            name: 'Restrict object access',
            attack_step: 'S0',
            attack_step_id: 'AT001-S1',
          },
        ],
      },
    ],
  });

  assert.equal(parsed.attack_trees[0]?.attack_steps[0]?.mitigations.length, 1);
  assert.equal(
    parsed.attack_trees[0]?.attack_steps[0]?.mitigations[0]?.attack_step_id,
    'AT001-S1',
  );
  assert.equal(parsed.attack_trees[0]?.mitigations.length, 1);
  assert.equal(
    parsed.attack_trees[0]?.attack_steps[0]?.ttp_mappings[0]?.attack_step_id,
    'AT001-S1',
  );
});
