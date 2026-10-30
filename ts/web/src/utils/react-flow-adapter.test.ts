import { describe, expect, it } from 'vitest';
import { adaptToReactFlow } from './react-flow-adapter';
import { parseMermaidToGraph } from './mermaid-parser';

describe('adaptToReactFlow mitigation associations', () => {
  it('merges direct, tree-level, and mapping mitigations onto the owning step', () => {
    const attackTree = {
      mermaid_code: 'graph TD\n  S0["Read object"] --> S1["Exfiltrate object"]',
      attack_steps: [
        {
          node_id: 'S0',
          label: 'Read object',
          description: 'Read object',
          mitigations: [
            { name: 'Restrict object access', attack_step: 'S0' },
            { name: 'Log object reads', attack_step: 'S0' },
          ],
        },
        {
          node_id: 'S1',
          label: 'Exfiltrate object',
          description: 'Exfiltrate object',
          ttp_mappings: [
            {
              attack_step: 'Exfiltrate object',
              attack_step_id: 'AT001-S2',
              node_id: 'S1',
              technique_id: 'T1048',
              technique_name: 'Exfiltration Over Alternative Protocol',
              confidence: 0.76,
            },
          ],
          mitigations: [],
        },
      ],
      mitigations: [
        {
          name: 'Restrict object access',
          attack_step: 'S0',
          technique_id: 'T1530',
        },
        {
          name: 'Detect cloud data access',
          technique_id: 'T1530',
        },
      ],
      ttc_mappings: [
        {
          attack_step: 'legacy description that no longer matches',
          technique_id: 'T1530',
          technique_name: 'Data from Cloud Storage',
          confidence: 0.82,
          mitigations: [{ name: 'Log object reads', attack_step: 'S0' }],
        },
      ],
    };
    const parsed = parseMermaidToGraph(
      attackTree.mermaid_code,
      attackTree.attack_steps,
    );

    const graph = adaptToReactFlow(parsed, attackTree);

    expect(graph.nodes.find((node) => node.id === 'S0')?.data.mitigations).toEqual([
      expect.objectContaining({ name: 'Restrict object access' }),
      expect.objectContaining({ name: 'Log object reads' }),
      expect.objectContaining({ name: 'Detect cloud data access' }),
    ]);
    expect(graph.nodes.find((node) => node.id === 'S0')?.data.ttcMappings).toEqual([
      expect.objectContaining({ technique_id: 'T1530' }),
    ]);
    expect(graph.nodes.find((node) => node.id === 'S1')?.data.mitigations).toEqual([]);
    expect(graph.nodes.find((node) => node.id === 'S1')?.data.ttcMappings).toEqual([
      expect.objectContaining({
        attack_step_id: 'AT001-S2',
        technique_id: 'T1048',
      }),
    ]);
  });
});
