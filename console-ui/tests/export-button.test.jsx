import { describe, it, expect, vi, afterEach } from 'vitest';
import React from 'react';
import { render, screen, cleanup, fireEvent } from '@testing-library/react';
import ExportButton from '../src/components/ExportButton.jsx';

vi.mock('../src/utils/export-service', () => ({
  exportCsv: vi.fn(),
  exportPdf: vi.fn(),
}));

import { exportCsv, exportPdf } from '../src/utils/export-service';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const validTree = {
  attack_steps: [
    { node_id: 'A', description: 'SQL Injection' },
    { node_id: 'B', description: 'XSS Attack' },
  ],
  ttc_mappings: [],
  mitigations: [],
};

const summaryData = {
  extraction_summary: { total_threats: 3, high_severity_count: 1 },
  mapping_summary: { total_mappings: 5 },
  attack_trees: [{}],
};

describe('ExportButton', () => {
  it('renders the Export button dropdown', () => {
    render(<ExportButton attackTree={validTree} summaryData={summaryData} />);
    expect(screen.getByText('Export')).toBeTruthy();
  });

  it('renders dropdown items when clicked', () => {
    render(<ExportButton attackTree={validTree} summaryData={summaryData} />);
    // Click the dropdown trigger to open it
    fireEvent.click(screen.getByText('Export'));
    expect(screen.getByText('Export PDF')).toBeTruthy();
    expect(screen.getByText('Export CSV')).toBeTruthy();
  });

  it('calls exportCsv with correct filename when CSV is selected', () => {
    render(
      <ExportButton attackTree={validTree} summaryData={summaryData} appId="myApp" versionId="v1" />
    );
    fireEvent.click(screen.getByText('Export'));
    fireEvent.click(screen.getByText('Export CSV'));
    expect(exportCsv).toHaveBeenCalledWith(validTree, 'attack-tree-myApp-v1.csv');
  });

  it('calls exportPdf with correct filename when PDF is selected', () => {
    render(
      <ExportButton attackTree={validTree} summaryData={summaryData} appId="myApp" versionId="v1" />
    );
    fireEvent.click(screen.getByText('Export'));
    fireEvent.click(screen.getByText('Export PDF'));
    expect(exportPdf).toHaveBeenCalledWith(validTree, summaryData, 'attack-tree-myApp-v1.pdf');
  });

  it('generates filename without appId/versionId when not provided', () => {
    render(<ExportButton attackTree={validTree} summaryData={summaryData} />);
    fireEvent.click(screen.getByText('Export'));
    fireEvent.click(screen.getByText('Export CSV'));
    expect(exportCsv).toHaveBeenCalledWith(validTree, 'attack-tree.csv');
  });

  it('shows error alert when attackTree is null', () => {
    render(<ExportButton attackTree={null} summaryData={summaryData} />);
    fireEvent.click(screen.getByText('Export'));
    fireEvent.click(screen.getByText('Export CSV'));
    expect(screen.getByText('No attack tree data available to export.')).toBeTruthy();
    expect(exportCsv).not.toHaveBeenCalled();
  });

  it('shows error alert when attackTree has no attack_steps', () => {
    render(<ExportButton attackTree={{}} summaryData={summaryData} />);
    fireEvent.click(screen.getByText('Export'));
    fireEvent.click(screen.getByText('Export PDF'));
    expect(screen.getByText('No attack tree data available to export.')).toBeTruthy();
    expect(exportPdf).not.toHaveBeenCalled();
  });

  it('shows error alert when attack_steps is empty array', () => {
    render(<ExportButton attackTree={{ attack_steps: [] }} summaryData={summaryData} />);
    fireEvent.click(screen.getByText('Export'));
    fireEvent.click(screen.getByText('Export CSV'));
    expect(screen.getByText('No attack tree data available to export.')).toBeTruthy();
    expect(exportCsv).not.toHaveBeenCalled();
  });

  it('does not show error alert initially', () => {
    render(<ExportButton attackTree={validTree} summaryData={summaryData} />);
    expect(screen.queryByText('No attack tree data available to export.')).toBeNull();
  });
});
