import { describe, it, expect } from 'vitest';
import { aggregateMitigations } from '../src/utils/mitigation-aggregator.js';

describe('aggregateMitigations', () => {
  it('returns empty array for null/undefined input', () => {
    expect(aggregateMitigations(null)).toEqual([]);
    expect(aggregateMitigations(undefined)).toEqual([]);
    expect(aggregateMitigations({})).toEqual([]);
  });

  it('returns empty array when attack tree has no mitigations anywhere', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'Step A' }],
      ttc_mappings: [{ attack_step: 'A', technique_id: 'T1190' }],
      mitigations: [],
    };
    expect(aggregateMitigations(tree)).toEqual([]);
  });

  it('collects mitigations from tree-level mitigations array', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'SQL Injection' }],
      ttc_mappings: [],
      mitigations: [
        { name: 'Input Validation', description: 'Validate all inputs', attack_step: 'A' },
      ],
    };
    const result = aggregateMitigations(tree);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Input Validation');
    expect(result[0].description).toBe('Validate all inputs');
    expect(result[0].attackSteps).toContain('SQL Injection');
  });

  it('collects mitigations from ttc_mappings[].mitigations', () => {
    const tree = {
      attack_steps: [{ node_id: 'B', description: 'XSS Attack' }],
      ttc_mappings: [
        {
          attack_step: 'B',
          technique_id: 'T1059',
          mitigations: [
            { name: 'Output Encoding', description: 'Encode output to prevent XSS' },
          ],
        },
      ],
      mitigations: [],
    };
    const result = aggregateMitigations(tree);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Output Encoding');
    expect(result[0].attackSteps).toContain('XSS Attack');
  });

  it('collects mitigations from attack_steps[].mitigations', () => {
    const tree = {
      attack_steps: [
        {
          node_id: 'C',
          description: 'Command Injection',
          mitigations: [
            { name: 'Parameterized Commands', description: 'Use parameterized commands' },
          ],
        },
      ],
      ttc_mappings: [],
      mitigations: [],
    };
    const result = aggregateMitigations(tree);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Parameterized Commands');
    expect(result[0].attackSteps).toContain('Command Injection');
  });

  it('deduplicates mitigations by name across sources', () => {
    const tree = {
      attack_steps: [
        { node_id: 'A', description: 'SQL Injection' },
        { node_id: 'B', description: 'XSS Attack' },
      ],
      ttc_mappings: [
        {
          attack_step: 'A',
          technique_id: 'T1190',
          mitigations: [
            { name: 'Input Validation', description: 'Validate all inputs' },
          ],
        },
      ],
      mitigations: [
        { name: 'Input Validation', description: 'Validate all inputs', attack_step: 'B' },
      ],
    };
    const result = aggregateMitigations(tree);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Input Validation');
    expect(result[0].attackSteps).toContain('SQL Injection');
    expect(result[0].attackSteps).toContain('XSS Attack');
  });

  it('collects all associated attack steps for a duplicated mitigation', () => {
    const tree = {
      attack_steps: [
        {
          node_id: 'A', description: 'Step A',
          mitigations: [{ name: 'WAF', description: 'Web Application Firewall' }],
        },
        {
          node_id: 'B', description: 'Step B',
          mitigations: [{ name: 'WAF', description: 'Web Application Firewall' }],
        },
        {
          node_id: 'C', description: 'Step C',
          mitigations: [{ name: 'WAF', description: 'Web Application Firewall' }],
        },
      ],
      ttc_mappings: [],
      mitigations: [],
    };
    const result = aggregateMitigations(tree);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('WAF');
    expect(result[0].attackSteps).toHaveLength(3);
    expect(result[0].attackSteps).toEqual(expect.arrayContaining(['Step A', 'Step B', 'Step C']));
  });

  it('handles multiple distinct mitigations', () => {
    const tree = {
      attack_steps: [],
      ttc_mappings: [],
      mitigations: [
        { name: 'MFA', description: 'Multi-factor auth', attack_step: 'Login' },
        { name: 'Rate Limiting', description: 'Limit requests', attack_step: 'API Call' },
        { name: 'Encryption', description: 'Encrypt data', attack_step: 'Data Store' },
      ],
    };
    const result = aggregateMitigations(tree);
    expect(result).toHaveLength(3);
    const names = result.map(r => r.name);
    expect(names).toContain('MFA');
    expect(names).toContain('Rate Limiting');
    expect(names).toContain('Encryption');
  });

  it('resolves attack step labels via node_id lookup', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'Privilege Escalation' }],
      ttc_mappings: [],
      mitigations: [
        { name: 'Least Privilege', description: 'Apply least privilege', attack_step: 'A' },
      ],
    };
    const result = aggregateMitigations(tree);
    expect(result[0].attackSteps).toContain('Privilege Escalation');
  });

  it('uses attack_step reference as fallback label when no match found', () => {
    const tree = {
      attack_steps: [],
      ttc_mappings: [],
      mitigations: [
        { name: 'Firewall', description: 'Network firewall', attack_step: 'Unknown Step' },
      ],
    };
    const result = aggregateMitigations(tree);
    expect(result[0].attackSteps).toContain('Unknown Step');
  });

  it('handles mitigations with alternate field names (mitigation, details)', () => {
    const tree = {
      attack_steps: [
        {
          node_id: 'A', description: 'Step A',
          mitigations: [{ mitigation: 'Alt Name', details: 'Alt description' }],
        },
      ],
      ttc_mappings: [],
      mitigations: [],
    };
    const result = aggregateMitigations(tree);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Alt Name');
    expect(result[0].description).toBe('Alt description');
  });

  it('skips mitigations without a name', () => {
    const tree = {
      attack_steps: [],
      ttc_mappings: [],
      mitigations: [
        { description: 'No name mitigation', attack_step: 'A' },
        { name: '', description: 'Empty name', attack_step: 'A' },
        { name: 'Valid', description: 'Has a name', attack_step: 'A' },
      ],
    };
    const result = aggregateMitigations(tree);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Valid');
  });

  it('handles attack_steps with label field', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', label: 'Short Label', description: 'Long description' }],
      ttc_mappings: [],
      mitigations: [
        { name: 'Fix', description: 'A fix', attack_step: 'A' },
      ],
    };
    const result = aggregateMitigations(tree);
    // Should resolve to the label (preferred over description)
    expect(result[0].attackSteps).toContain('Short Label');
  });
});
