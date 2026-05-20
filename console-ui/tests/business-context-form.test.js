import { describe, it, expect } from 'vitest';
import {
  emptyBusinessContext,
  validateBusinessContext,
  normaliseCiaPriority,
  DATA_SENSITIVITY_OPTIONS,
  CIA_DEFAULT_ORDER,
} from '../src/components/BusinessContextForm.jsx';

/**
 * Tests for the pure helpers exported alongside BusinessContextForm.
 * The JSX rendering is covered by the CreateApplicationPage test suite;
 * here we just pin the shape + validation contract.
 */

describe('emptyBusinessContext', () => {
  it('returns all required keys with empty defaults and the canonical CIA order', () => {
    const ctx = emptyBusinessContext();
    expect(ctx).toEqual({
      description: '',
      regulatory_frameworks: [],
      data_sensitivity: '',
      cia_priority: ['confidentiality', 'integrity', 'availability'],
    });
  });

  it('returns a fresh object each call (safe to mutate)', () => {
    const a = emptyBusinessContext();
    a.regulatory_frameworks.push('SOC2');
    expect(emptyBusinessContext().regulatory_frameworks).toEqual([]);
    a.cia_priority.reverse();
    expect(emptyBusinessContext().cia_priority).toEqual(CIA_DEFAULT_ORDER);
  });
});

describe('validateBusinessContext', () => {
  const complete = {
    description: 'A demo app.',
    regulatory_frameworks: ['SOC2'],
    data_sensitivity: 'pii',
    cia_priority: ['integrity', 'confidentiality', 'availability'],
  };

  it('returns an empty errors object when all fields are set', () => {
    expect(validateBusinessContext(complete)).toEqual({});
  });

  it('flags missing description', () => {
    expect(validateBusinessContext({ ...complete, description: '   ' })).toHaveProperty(
      'description'
    );
  });

  it('flags empty regulatory_frameworks', () => {
    expect(
      validateBusinessContext({ ...complete, regulatory_frameworks: [] })
    ).toHaveProperty('regulatory_frameworks');
  });

  it('flags missing data_sensitivity', () => {
    expect(
      validateBusinessContext({ ...complete, data_sensitivity: '' })
    ).toHaveProperty('data_sensitivity');
  });

  it('flags malformed cia_priority — wrong length', () => {
    expect(
      validateBusinessContext({ ...complete, cia_priority: ['confidentiality'] })
    ).toHaveProperty('cia_priority');
  });

  it('flags malformed cia_priority — duplicate value', () => {
    expect(
      validateBusinessContext({
        ...complete,
        cia_priority: ['integrity', 'integrity', 'availability'],
      })
    ).toHaveProperty('cia_priority');
  });

  it('flags missing cia_priority entirely', () => {
    const { cia_priority, ...rest } = complete;
    expect(validateBusinessContext(rest)).toHaveProperty('cia_priority');
  });

  it('accepts the data_sensitivity "unknown" sentinel', () => {
    expect(
      validateBusinessContext({ ...complete, data_sensitivity: 'unknown' })
    ).toEqual({});
  });
});

describe('normaliseCiaPriority', () => {
  it('passes a valid ranking through untouched', () => {
    expect(normaliseCiaPriority(['integrity', 'confidentiality', 'availability'])).toEqual([
      'integrity',
      'confidentiality',
      'availability',
    ]);
  });

  it('returns the canonical order when input is missing or malformed', () => {
    expect(normaliseCiaPriority(undefined)).toEqual(CIA_DEFAULT_ORDER);
    expect(normaliseCiaPriority(null)).toEqual(CIA_DEFAULT_ORDER);
    expect(normaliseCiaPriority('confidentiality')).toEqual(CIA_DEFAULT_ORDER);
  });

  it('drops duplicates and unknowns, then fills missing in canonical order', () => {
    expect(
      normaliseCiaPriority(['integrity', 'integrity', 'foo', 'availability'])
    ).toEqual(['integrity', 'availability', 'confidentiality']);
  });
});

describe('option lists', () => {
  it('data_sensitivity options cover every backend literal', () => {
    const expected = [
      'public',
      'internal',
      'confidential',
      'highly_confidential',
      'pii',
      'phi',
      'regulated_financial',
      'unknown',
    ];
    expect(DATA_SENSITIVITY_OPTIONS.map((o) => o.value).sort()).toEqual(expected.sort());
  });
});
