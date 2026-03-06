import { describe, it, expect, afterEach } from 'vitest';
import React from 'react';
import { render, screen, cleanup } from '@testing-library/react';
import MitigationsTable from '../src/components/MitigationsTable.jsx';

afterEach(cleanup);

const treeWithMitigations = {
  attack_steps: [
    {
      node_id: 'A',
      description: 'SQL Injection',
      mitigations: [
        { name: 'Input Validation', description: 'Validate all user inputs.' },
      ],
    },
    {
      node_id: 'B',
      description: 'XSS Attack',
      mitigations: [
        { name: 'Output Encoding', description: 'Encode output to prevent XSS.' },
        { name: 'Input Validation', description: 'Validate all user inputs.' },
      ],
    },
  ],
  ttc_mappings: [],
  mitigations: [],
};

const treeNoMitigations = {
  attack_steps: [{ node_id: 'A', description: 'Step A' }],
  ttc_mappings: [],
  mitigations: [],
};

describe('MitigationsTable', () => {
  it('renders the table header with mitigation count', () => {
    render(<MitigationsTable attackTree={treeWithMitigations} />);
    expect(screen.getByText('Mitigations Summary')).toBeTruthy();
    expect(screen.getByText('(2)')).toBeTruthy();
  });

  it('renders column headers', () => {
    render(<MitigationsTable attackTree={treeWithMitigations} />);
    expect(screen.getByText('Mitigation Title')).toBeTruthy();
    expect(screen.getByText('Description')).toBeTruthy();
    expect(screen.getByText('Associated Attack Steps')).toBeTruthy();
  });

  it('renders deduplicated mitigation rows', () => {
    render(<MitigationsTable attackTree={treeWithMitigations} />);
    expect(screen.getByText('Input Validation')).toBeTruthy();
    expect(screen.getByText('Output Encoding')).toBeTruthy();
  });

  it('renders descriptions for mitigations', () => {
    render(<MitigationsTable attackTree={treeWithMitigations} />);
    expect(screen.getByText('Validate all user inputs.')).toBeTruthy();
    expect(screen.getByText('Encode output to prevent XSS.')).toBeTruthy();
  });

  it('renders associated attack steps as badges', () => {
    render(<MitigationsTable attackTree={treeWithMitigations} />);
    // Input Validation is associated with both SQL Injection and XSS Attack
    // XSS Attack appears in two rows (Input Validation + Output Encoding), so use getAllByText
    expect(screen.getByText('SQL Injection')).toBeTruthy();
    expect(screen.getAllByText('XSS Attack').length).toBeGreaterThanOrEqual(1);
  });

  it('shows empty state when no mitigations exist', () => {
    render(<MitigationsTable attackTree={treeNoMitigations} />);
    expect(screen.getByText('No mitigations available')).toBeTruthy();
  });

  it('shows empty state for null attackTree', () => {
    render(<MitigationsTable attackTree={null} />);
    expect(screen.getByText('No mitigations available')).toBeTruthy();
  });

  it('shows empty state for undefined attackTree', () => {
    render(<MitigationsTable attackTree={undefined} />);
    expect(screen.getByText('No mitigations available')).toBeTruthy();
  });

  it('renders count of zero when no mitigations', () => {
    render(<MitigationsTable attackTree={treeNoMitigations} />);
    expect(screen.getByText('(0)')).toBeTruthy();
  });
});
