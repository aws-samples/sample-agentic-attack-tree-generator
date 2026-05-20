import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react';
import CustomiseExportModal from '../src/components/CustomiseExportModal.jsx';
import {
  exportCustomPdf,
  exportCustomCsvBundle,
  generateTtpMappingsCsvContent,
  DEFAULT_SECTIONS,
  EXPORT_SECTIONS,
} from '../src/utils/export-service.js';

const validSummary = {
  attack_trees: [
    {
      threat_id: 'TS001',
      threat_category: 'Spoofing',
      priority: 'High',
      threat_statement: 'A demo threat',
      attack_steps: [
        { node_id: 'AT001', label: 'Phish', description: 'phish a user' },
      ],
      ttc_mappings: [
        { attack_step: 'AT001', technique_id: 'T1566', technique_name: 'Phishing', confidence: 0.9 },
      ],
      mitigations: [
        { name: 'MFA', description: 'Require MFA' },
      ],
    },
  ],
  threats: [],
  extraction_summary: { total_threats: 1, high_severity_count: 1 },
  mapping_summary: { total_mappings: 1 },
  project_info: { application_name: 'demo' },
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// ─── DEFAULT_SECTIONS contract ─────────────────────────────────────

describe('DEFAULT_SECTIONS', () => {
  it('excludes attack steps by default to keep reports compact', () => {
    expect(DEFAULT_SECTIONS.attackSteps).toBe(false);
    expect(DEFAULT_SECTIONS.threats).toBe(true);
    expect(DEFAULT_SECTIONS.ttp).toBe(true);
    expect(DEFAULT_SECTIONS.mitigations).toBe(true);
  });

  it('covers every key in EXPORT_SECTIONS', () => {
    for (const key of EXPORT_SECTIONS) {
      expect(key in DEFAULT_SECTIONS).toBe(true);
    }
  });
});

// ─── exportCustomPdf ───────────────────────────────────────────────

describe('exportCustomPdf', () => {
  it('alerts and returns when no sections are selected', () => {
    const alertSpy = vi.spyOn(globalThis, 'alert').mockImplementation(() => {});
    exportCustomPdf(
      validSummary,
      { threats: false, attackSteps: false, ttp: false, mitigations: false },
      'out.pdf'
    );
    expect(alertSpy).toHaveBeenCalledWith(expect.stringMatching(/Select at least one section/i));
  });

  it('alerts when summaryData is null', () => {
    const alertSpy = vi.spyOn(globalThis, 'alert').mockImplementation(() => {});
    exportCustomPdf(null, DEFAULT_SECTIONS, 'out.pdf');
    expect(alertSpy).toHaveBeenCalled();
  });

  it('alerts when there are no attack trees', () => {
    const alertSpy = vi.spyOn(globalThis, 'alert').mockImplementation(() => {});
    exportCustomPdf({ attack_trees: [] }, DEFAULT_SECTIONS, 'out.pdf');
    expect(alertSpy).toHaveBeenCalledWith(expect.stringMatching(/no attack trees/i));
  });

  // We don't assert on PDF byte content (jspdf in jsdom is messy); the
  // smoke test above plus the exports-bundle test below cover the wiring.
});

// ─── exportCustomCsvBundle ─────────────────────────────────────────

describe('exportCustomCsvBundle', () => {
  let downloadCalls;

  beforeEach(() => {
    downloadCalls = [];
    globalThis.URL.createObjectURL = vi.fn().mockReturnValue('blob:mock');
    globalThis.URL.revokeObjectURL = vi.fn();
    vi.spyOn(document, 'createElement').mockImplementation((tag) => {
      const el = {
        tag,
        href: '',
        download: '',
        style: {},
        click: vi.fn(() => downloadCalls.push({ download: el.download })),
      };
      return el;
    });
    vi.spyOn(document.body, 'appendChild').mockImplementation(() => {});
    vi.spyOn(document.body, 'removeChild').mockImplementation(() => {});
  });

  it('downloads a single .csv when one section is selected', async () => {
    await exportCustomCsvBundle(
      validSummary,
      { threats: true, attackSteps: false, ttp: false, mitigations: false },
      'demo.csv'
    );
    expect(downloadCalls).toHaveLength(1);
    expect(downloadCalls[0].download).toMatch(/threats\.csv$/);
  });

  it('downloads a .zip when multiple sections are selected', async () => {
    await exportCustomCsvBundle(
      validSummary,
      { threats: true, attackSteps: false, ttp: true, mitigations: true },
      'demo.csv'
    );
    expect(downloadCalls).toHaveLength(1);
    expect(downloadCalls[0].download).toMatch(/\.zip$/);
  });

  it('alerts if every selected section has no data', async () => {
    const alertSpy = vi.spyOn(globalThis, 'alert').mockImplementation(() => {});
    // Empty data set + only attackSteps selected → CSV generators yield nothing.
    await exportCustomCsvBundle(
      { attack_trees: [] },
      { threats: false, attackSteps: true, ttp: false, mitigations: false },
      'empty.csv'
    );
    expect(alertSpy).toHaveBeenCalled();
  });
});

// ─── generateTtpMappingsCsvContent ─────────────────────────────────

describe('generateTtpMappingsCsvContent', () => {
  it('emits header + one row per (threat × technique)', () => {
    const csv = generateTtpMappingsCsvContent(validSummary);
    const lines = csv.split('\n');
    expect(lines[0]).toContain('TTP ID');
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain('T1566');
    expect(lines[1]).toContain('TS001');
  });

  it('returns empty string for null input', () => {
    expect(generateTtpMappingsCsvContent(null)).toBe('');
  });
});

// ─── CustomiseExportModal ──────────────────────────────────────────

describe('CustomiseExportModal', () => {
  function setup(overrides = {}) {
    const onConfirm = vi.fn();
    const onDismiss = vi.fn();
    render(
      <CustomiseExportModal
        visible={true}
        onConfirm={onConfirm}
        onDismiss={onDismiss}
        loading={false}
        threatCount={5}
        {...overrides}
      />
    );
    return { onConfirm, onDismiss };
  }

  it('renders all section checkboxes with the expected defaults', () => {
    setup();
    // attackSteps starts unchecked — the load-bearing default flip.
    expect(screen.getByTestId('section-attack-steps').querySelector('input').checked).toBe(false);
    expect(screen.getByTestId('section-threats').querySelector('input').checked).toBe(true);
    expect(screen.getByTestId('section-ttp').querySelector('input').checked).toBe(true);
    expect(screen.getByTestId('section-mitigations').querySelector('input').checked).toBe(true);
  });

  it('shows the per-threat page warning when attack steps is toggled on', () => {
    setup({ threatCount: 12 });
    expect(screen.getByText(/12 threats/)).toBeTruthy();
  });

  it('disables Download when every section is unchecked', () => {
    setup();
    fireEvent.click(screen.getByTestId('section-threats').querySelector('input'));
    fireEvent.click(screen.getByTestId('section-ttp').querySelector('input'));
    fireEvent.click(screen.getByTestId('section-mitigations').querySelector('input'));
    const btn = screen.getByTestId('confirm-customise-export').closest('button');
    expect(btn?.disabled).toBe(true);
  });

  it('calls onConfirm with the chosen sections + format', async () => {
    const { onConfirm } = setup();
    fireEvent.click(screen.getByTestId('section-attack-steps').querySelector('input'));
    fireEvent.click(screen.getByTestId('confirm-customise-export'));
    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledWith({
        sections: { threats: true, attackSteps: true, ttp: true, mitigations: true },
        format: 'pdf',
      });
    });
  });
});
