import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import ImportReportButton from '../src/components/ImportReportButton.jsx';

vi.mock('../src/api-client', () => ({
  getImportsInfo: vi.fn(),
  uploadTfReport: vi.fn(),
}));

import { getImportsInfo, uploadTfReport } from '../src/api-client';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

beforeEach(() => {
  // Default — info endpoint returns a path; tests can override.
  getImportsInfo.mockResolvedValue({
    imports_dir: '/abs/path/to/imports',
    processed: [],
    failed: [],
  });
});

describe('ImportReportButton', () => {
  it('opens the modal when clicked', () => {
    render(<ImportReportButton onImported={() => {}} />);
    fireEvent.click(screen.getByTestId('import-report-button'));
    expect(screen.getByText(/Import a ThreatForest report/i)).toBeTruthy();
  });

  it('uploads the chosen file and shows the imported success message', async () => {
    uploadTfReport.mockResolvedValue({
      result: {
        bundle: 'demo.tfreport',
        status: 'imported',
        folder_name: 'demo',
        versions_added: ['20260101_120000'],
        versions_skipped: [],
        error: null,
      },
    });
    const onImported = vi.fn();

    render(<ImportReportButton onImported={onImported} />);
    fireEvent.click(screen.getByTestId('import-report-button'));

    const file = new File(['fake-zip'], 'demo.tfreport', { type: 'application/zip' });
    const input = screen.getByTestId('import-report-file-input');
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => {
      expect(uploadTfReport).toHaveBeenCalledWith(file);
    });
    await waitFor(() => {
      // Alert renders both a header ("Imported") and body text containing
      // the folder name; checking for the body text is more specific than
      // the bare header.
      expect(screen.getByText(/Application imported as/i)).toBeTruthy();
    });
    expect(onImported).toHaveBeenCalledWith(
      expect.objectContaining({ status: 'imported', folder_name: 'demo' })
    );
  });

  it('rejects files that do not end in .tfreport without calling the server', () => {
    render(<ImportReportButton onImported={() => {}} />);
    fireEvent.click(screen.getByTestId('import-report-button'));
    const file = new File(['x'], 'demo.zip', { type: 'application/zip' });
    fireEvent.change(screen.getByTestId('import-report-file-input'), {
      target: { files: [file] },
    });
    expect(uploadTfReport).not.toHaveBeenCalled();
    expect(screen.getByText(/ends in \.tfreport/i)).toBeTruthy();
  });

  it('surfaces the server error on a failed upload', async () => {
    uploadTfReport.mockRejectedValue(new Error('Bundle exceeds the 200 MB limit.'));

    render(<ImportReportButton onImported={() => {}} />);
    fireEvent.click(screen.getByTestId('import-report-button'));
    const file = new File(['x'], 'big.tfreport', { type: 'application/zip' });
    fireEvent.change(screen.getByTestId('import-report-file-input'), {
      target: { files: [file] },
    });

    await waitFor(() => {
      expect(screen.getByText(/200 MB limit/)).toBeTruthy();
    });
  });

  it('shows a merged-status alert without firing onImported a second time for the same upload', async () => {
    uploadTfReport.mockResolvedValue({
      result: {
        bundle: 'demo-v2.tfreport',
        status: 'merged',
        folder_name: 'demo',
        versions_added: ['20260202_120000'],
        versions_skipped: [],
        error: null,
      },
    });
    const onImported = vi.fn();

    render(<ImportReportButton onImported={onImported} />);
    fireEvent.click(screen.getByTestId('import-report-button'));
    fireEvent.change(screen.getByTestId('import-report-file-input'), {
      target: { files: [new File(['x'], 'demo-v2.tfreport')] },
    });

    await waitFor(() => {
      expect(screen.getByText(/Merged into existing app/i)).toBeTruthy();
    });
    expect(onImported).toHaveBeenCalledTimes(1);
  });
});
