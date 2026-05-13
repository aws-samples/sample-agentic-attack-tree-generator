import { describe, it, expect } from 'vitest';
import {
  MITIGATION_STATUSES,
  STATUS_OPTIONS,
  TERMINAL_STATUSES,
  isTerminal,
  statusInfo,
} from '../src/utils/mitigation-status';

describe('mitigation-status helpers', () => {
  it('exposes the canonical 5-status enum in the documented order', () => {
    expect(MITIGATION_STATUSES.map((s) => s.value)).toEqual([
      'already_implemented',
      'in_progress',
      'accepted_risk',
      'not_relevant',
      'wont_do',
    ]);
  });

  it("includes a synthetic 'no status' option at the top of the dropdown", () => {
    expect(STATUS_OPTIONS[0]).toEqual({ value: '', label: 'Open (no status)' });
    expect(STATUS_OPTIONS).toHaveLength(MITIGATION_STATUSES.length + 1);
  });

  it('every enum value has a label and a Cloudscape colour', () => {
    for (const s of MITIGATION_STATUSES) {
      expect(typeof s.label).toBe('string');
      expect(s.label.length).toBeGreaterThan(0);
      expect(typeof s.color).toBe('string');
      expect(s.color.length).toBeGreaterThan(0);
    }
  });

  describe('statusInfo', () => {
    it('returns the record for a known status', () => {
      expect(statusInfo('already_implemented')).toMatchObject({
        value: 'already_implemented',
        label: 'Already implemented',
      });
    });

    it('returns null for falsy / unknown values', () => {
      expect(statusInfo(null)).toBeNull();
      expect(statusInfo('')).toBeNull();
      expect(statusInfo('made_up')).toBeNull();
    });
  });

  describe('isTerminal', () => {
    it('marks resolved dispositions as terminal', () => {
      expect(isTerminal('already_implemented')).toBe(true);
      expect(isTerminal('not_relevant')).toBe(true);
      expect(isTerminal('wont_do')).toBe(true);
      expect(isTerminal('accepted_risk')).toBe(true);
    });

    it('leaves in-progress and unknown / null statuses non-terminal', () => {
      expect(isTerminal('in_progress')).toBe(false);
      expect(isTerminal(null)).toBe(false);
      expect(isTerminal('')).toBe(false);
      expect(isTerminal('open')).toBe(false);
    });
  });

  it('TERMINAL_STATUSES is exactly the resolved-disposition set', () => {
    expect(TERMINAL_STATUSES).toEqual(
      new Set(['already_implemented', 'not_relevant', 'wont_do', 'accepted_risk'])
    );
  });
});
