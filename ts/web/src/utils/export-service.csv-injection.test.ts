/**
 * Regression test for CSV formula injection (CWE-1236) in the CSV exporters.
 *
 * Threat/mitigation text is LLM-extracted from user-controllable repo content,
 * so a value beginning with `= + - @` (or a leading tab/CR) must be neutralized
 * before it lands in a downloadable .csv, or Excel/Sheets would evaluate it as a
 * formula. escapeCsvField is not exported, so we exercise it through the public
 * generators.
 */
import { describe, it, expect } from 'vitest';
import {
  generateThreatsCsvContent,
  generateThreatsOnlyCsvContent,
  type ThreatModelSummary,
} from './export-service.js';

function summaryWith(statement: string, category: string): ThreatModelSummary {
  return {
    attack_trees: [
      {
        threat_id: 'T1',
        threat_category: category,
        priority: 'High',
        threat_statement: statement,
        attack_steps: [],
      },
    ],
    threats: [],
  } as unknown as ThreatModelSummary;
}

describe('CSV formula injection neutralization', () => {
  const dangerous = [
    '=cmd|/c calc',
    '+1+1',
    '-2+3',
    '@SUM(A1:A9)',
    '\t=evil',
    '\r=evil',
  ];

  for (const payload of dangerous) {
    it(`prefixes a leading formula char with a single quote: ${JSON.stringify(payload)}`, () => {
      const csv = generateThreatsCsvContent(summaryWith(payload, 'Spoofing'));
      // The data row is everything after the header line.
      const dataRow = csv.split('\n')[1] ?? '';
      // The payload must appear quote-prefixed ('...) somewhere in the row, and
      // must NOT appear as a bare leading formula token in any cell.
      expect(dataRow).toContain("'" + payload.replace(/"/g, '""'));
      for (const cell of splitCsvRow(dataRow)) {
        expect(/^[=+\-@\t\r]/.test(cell)).toBe(false);
      }
    });
  }

  it('leaves benign values untouched (no spurious quote)', () => {
    const csv = generateThreatsOnlyCsvContent(summaryWith('SQL injection in login', 'Tampering'));
    const dataRow = csv.split('\n')[1] ?? '';
    expect(dataRow).toContain('SQL injection in login');
    expect(dataRow).not.toContain("'SQL injection");
  });
});

/** Split a single CSV row into unescaped cell values (handles RFC-4180 quoting). */
function splitCsvRow(row: string): string[] {
  const cells: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < row.length; i++) {
    const c = row[i];
    if (inQuotes) {
      if (c === '"' && row[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === '"') {
        inQuotes = false;
      } else {
        cur += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      cells.push(cur);
      cur = '';
    } else {
      cur += c;
    }
  }
  cells.push(cur);
  return cells;
}
