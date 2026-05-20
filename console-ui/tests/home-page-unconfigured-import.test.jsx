import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../src/api-client', () => ({
  getPausedRuns: vi.fn(),
  getActiveRuns: vi.fn(),
  getConfig: vi.fn(),
  getApplications: vi.fn(),
  getImportsInfo: vi.fn(),
  uploadTfReport: vi.fn(),
}));

import HomePage from '../src/pages/HomePage.jsx';
import {
  getPausedRuns,
  getActiveRuns,
  getConfig,
  getApplications,
  getImportsInfo,
  uploadTfReport,
} from '../src/api-client';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  try { window.localStorage.clear(); } catch (_) { /* ignore */ }
});

beforeEach(() => {
  getPausedRuns.mockResolvedValue({ paused_runs: [] });
  getActiveRuns.mockResolvedValue({ runs: [] });
  getApplications.mockResolvedValue({ applications: [] });
  // Empty config simulates a fresh install — no provider, no model.
  getConfig.mockResolvedValue({});
  getImportsInfo.mockResolvedValue({
    imports_dir: '/abs/path/to/imports',
    processed: [],
    failed: [],
  });
});

function renderHomePage() {
  return render(
    <MemoryRouter>
      <HomePage />
    </MemoryRouter>
  );
}

describe('HomePage — fresh-install import flow', () => {
  it('shows Import a report alongside Configure model access on the unconfigured state', async () => {
    renderHomePage();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /configure model access/i })).toBeTruthy();
    });
    expect(screen.getByTestId('import-report-button')).toBeTruthy();
  });

  it('navigates to /applications after a successful import without requiring config', async () => {
    uploadTfReport.mockResolvedValue({
      result: {
        bundle: 'shared.tfreport',
        status: 'imported',
        folder_name: 'shared-app',
        versions_added: ['20260520_140000'],
        versions_skipped: [],
        error: null,
      },
    });

    renderHomePage();
    await waitFor(() => {
      expect(screen.getByTestId('import-report-button')).toBeTruthy();
    });

    fireEvent.click(screen.getByTestId('import-report-button'));
    const file = new File(['fake-zip'], 'shared.tfreport', { type: 'application/zip' });
    const input = screen.getByTestId('import-report-file-input');
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/applications');
    });
  });
});
