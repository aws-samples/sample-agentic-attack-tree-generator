import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateCsvContent, exportCsv, exportPdf } from '../src/utils/export-service.js';

describe('generateCsvContent', () => {
  it('returns empty string for null/undefined input', () => {
    expect(generateCsvContent(null)).toBe('');
    expect(generateCsvContent(undefined)).toBe('');
    expect(generateCsvContent({})).toBe('');
  });

  it('returns empty string when attack_steps is empty', () => {
    const tree = { attack_steps: [], ttc_mappings: [], mitigations: [] };
    expect(generateCsvContent(tree)).toBe('');
  });

  it('produces header row plus one data row per attack step', () => {
    const tree = {
      attack_steps: [
        { node_id: 'A', description: 'SQL Injection' },
        { node_id: 'B', description: 'XSS Attack' },
      ],
      ttc_mappings: [],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    const lines = csv.split('\n');
    expect(lines).toHaveLength(3); // header + 2 data rows
    expect(lines[0]).toBe('Step Name,Step Description,MITRE Technique IDs,MITRE Technique Names,Mitigation Names');
  });

  it('includes step name and description in each row', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'SQL Injection' }],
      ttc_mappings: [],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('SQL Injection');
  });

  it('includes MITRE technique IDs and names separated by semicolons', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'SQL Injection' }],
      ttc_mappings: [
        { attack_step: 'A', technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application' },
        { attack_step: 'A', technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter' },
      ],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('T1190;T1059');
    expect(dataRow).toContain('Exploit Public-Facing Application;Command and Scripting Interpreter');
  });

  it('includes mitigation names separated by semicolons', () => {
    const tree = {
      attack_steps: [
        {
          node_id: 'A', description: 'SQL Injection',
          mitigations: [
            { name: 'Input Validation', description: 'Validate inputs' },
            { name: 'WAF', description: 'Web Application Firewall' },
          ],
        },
      ],
      ttc_mappings: [],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('Input Validation;WAF');
  });

  it('escapes fields containing commas per RFC 4180', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'Step with, comma' }],
      ttc_mappings: [],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('"Step with, comma"');
  });

  it('escapes fields containing double quotes per RFC 4180', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'Step with "quotes"' }],
      ttc_mappings: [],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('"Step with ""quotes"""');
  });

  it('escapes fields containing newlines per RFC 4180', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'Line1\nLine2' }],
      ttc_mappings: [],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    // The field should be wrapped in quotes
    expect(csv).toContain('"Line1\nLine2"');
  });

  it('collects mitigations from tree-level mitigations array', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'SQL Injection' }],
      ttc_mappings: [],
      mitigations: [
        { name: 'Input Validation', description: 'Validate inputs', attack_step: 'A' },
      ],
    };
    const csv = generateCsvContent(tree);
    expect(csv).toContain('Input Validation');
  });

  it('collects mitigations from ttc_mappings[].mitigations', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', description: 'SQL Injection' }],
      ttc_mappings: [
        {
          attack_step: 'A',
          technique_id: 'T1190',
          technique_name: 'Exploit',
          mitigations: [{ name: 'WAF', description: 'Firewall' }],
        },
      ],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    expect(csv).toContain('WAF');
  });

  it('uses label field as step name when available', () => {
    const tree = {
      attack_steps: [{ node_id: 'A', label: 'Short Label', description: 'Long description' }],
      ttc_mappings: [],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    const dataRow = csv.split('\n')[1];
    // First field should be the label
    expect(dataRow.startsWith('Short Label,')).toBe(true);
  });

  it('deduplicates mitigation names for a single step', () => {
    const tree = {
      attack_steps: [
        {
          node_id: 'A', description: 'SQL Injection',
          mitigations: [{ name: 'WAF', description: 'Firewall' }],
        },
      ],
      ttc_mappings: [
        {
          attack_step: 'A',
          technique_id: 'T1190',
          technique_name: 'Exploit',
          mitigations: [{ name: 'WAF', description: 'Firewall' }],
        },
      ],
      mitigations: [],
    };
    const csv = generateCsvContent(tree);
    const dataRow = csv.split('\n')[1];
    // WAF should appear only once, not WAF;WAF
    const mitigationField = dataRow.split(',').pop();
    expect(mitigationField).toBe('WAF');
  });
});

describe('exportCsv', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows alert when attack tree is empty', () => {
    const alertSpy = vi.spyOn(globalThis, 'alert').mockImplementation(() => {});
    exportCsv(null, 'test.csv');
    expect(alertSpy).toHaveBeenCalledWith('No attack tree data available to export.');
  });

  it('creates a download link for valid data', () => {
    // jsdom doesn't have URL.createObjectURL, so we stub it
    const mockUrl = 'blob:mock-url';
    globalThis.URL.createObjectURL = vi.fn().mockReturnValue(mockUrl);
    globalThis.URL.revokeObjectURL = vi.fn();

    const clickSpy = vi.fn();
    vi.spyOn(document, 'createElement').mockReturnValue({
      href: '',
      download: '',
      style: {},
      click: clickSpy,
    });
    vi.spyOn(document.body, 'appendChild').mockImplementation(() => {});
    vi.spyOn(document.body, 'removeChild').mockImplementation(() => {});

    const tree = {
      attack_steps: [{ node_id: 'A', description: 'Test Step' }],
      ttc_mappings: [],
      mitigations: [],
    };

    exportCsv(tree, 'test-export.csv');

    expect(globalThis.URL.createObjectURL).toHaveBeenCalled();
    expect(clickSpy).toHaveBeenCalled();
    expect(globalThis.URL.revokeObjectURL).toHaveBeenCalledWith(mockUrl);
  });
});

describe('exportPdf', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows alert when attack tree is null', () => {
    const alertSpy = vi.spyOn(globalThis, 'alert').mockImplementation(() => {});
    exportPdf(null, {}, 'test.pdf');
    expect(alertSpy).toHaveBeenCalledWith('No attack tree data available to export.');
  });

  it('shows alert when attack_steps is empty', () => {
    const alertSpy = vi.spyOn(globalThis, 'alert').mockImplementation(() => {});
    exportPdf({ attack_steps: [] }, {}, 'test.pdf');
    expect(alertSpy).toHaveBeenCalledWith('No attack steps available to export.');
  });
});
