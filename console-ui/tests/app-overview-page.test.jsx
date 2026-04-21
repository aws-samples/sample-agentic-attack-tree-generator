import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AppOverviewPage from '../src/pages/AppOverviewPage.jsx';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../src/api-client', () => ({
  getApplication: vi.fn(),
  getApplicationVersions: vi.fn(),
  updateApplication: vi.fn(),
  deleteApplicationRecord: vi.fn(),
  pickDirectory: vi.fn(),
}));

import {
  getApplication,
  getApplicationVersions,
  updateApplication,
  deleteApplicationRecord,
} from '../src/api-client';

const SAMPLE_APP = {
  id: 'app_abc',
  name: 'Healthcare Intake',
  slug: 'healthcare-intake',
  project_path: '/tmp/healthcare',
  run_dir_name: 'healthcare-intake',
  business_context: {
    description: 'A healthcare intake API.',
    regulatory_frameworks: ['HIPAA'],
    data_sensitivity: 'phi',
    main_cia_risk: 'confidentiality',
  },
};

function renderPage(appId = 'app_abc') {
  return render(
    <MemoryRouter initialEntries={[`/applications/${appId}`]}>
      <Routes>
        <Route path="/applications/:appId" element={<AppOverviewPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('AppOverviewPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('shows a spinner while loading', () => {
    getApplication.mockReturnValue(new Promise(() => {}));
    getApplicationVersions.mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getAllByTestId('loading-spinner').length).toBeGreaterThan(0);
  });

  it('renders the app name and business context once loaded', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({ versions: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Healthcare Intake').length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText('A healthcare intake API.').length).toBeGreaterThan(0);
    expect(screen.getAllByText('HIPAA').length).toBeGreaterThan(0);
  });

  it('renders the latest threat model when versions are available', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({
      versions: [
        {
          id: 'v2',
          run_date: '2026-03-10T12:00:00Z',
          status: 'completed',
          threat_count: 7,
          high_severity_count: 2,
          categories: [],
        },
        {
          id: 'v1',
          run_date: '2026-01-02T08:00:00Z',
          status: 'completed',
          threat_count: 4,
          high_severity_count: 1,
          categories: [],
        },
      ],
    });
    renderPage();
    await waitFor(() => {
      // The latest version id appears in both the latest-model card and the table.
      expect(screen.getAllByText(/v2/).length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText('Completed').length).toBeGreaterThan(0);
  });

  it('renders an empty state with a Start CTA when no versions exist', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({ versions: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('No threat models yet').length).toBeGreaterThan(0);
    });
  });

  it('navigates to the run wizard when "Start new threat model" is clicked', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({ versions: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByTestId('start-new-threat-model').length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByTestId('start-new-threat-model')[0]);
    expect(mockNavigate).toHaveBeenCalledWith('/applications/app_abc/runs/new');
  });

  it('renames the application via updateApplication when Save is pressed', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({ versions: [] });
    updateApplication.mockResolvedValueOnce({ ...SAMPLE_APP, name: 'Renamed' });

    renderPage();
    await waitFor(() => {
      expect(screen.getAllByTestId('rename-app').length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByTestId('rename-app')[0]);

    await waitFor(() => {
      expect(screen.getAllByTestId('rename-input').length).toBeGreaterThan(0);
    });
    // Cloudscape's Input forwards data-testid to the inner <input>; grab it
    // and fire a change event.
    const testidEls = screen.getAllByTestId('rename-input');
    const input = testidEls[0].querySelector('input') || testidEls[0];
    fireEvent.change(input, { target: { value: 'Renamed' } });

    fireEvent.click(screen.getAllByTestId('save-rename')[0]);
    await waitFor(() => {
      expect(updateApplication).toHaveBeenCalledWith('app_abc', { name: 'Renamed' });
    });
  });

  it('deletes the application and navigates back to the list', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({ versions: [] });
    deleteApplicationRecord.mockResolvedValueOnce({ success: true });

    renderPage();
    await waitFor(() => {
      expect(screen.getAllByTestId('delete-app').length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByTestId('delete-app')[0]);
    await waitFor(() => {
      expect(screen.getAllByTestId('confirm-delete').length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByTestId('confirm-delete')[0]);
    await waitFor(() => {
      expect(deleteApplicationRecord).toHaveBeenCalledWith('app_abc');
      expect(mockNavigate).toHaveBeenCalledWith('/applications');
    });
  });

  it('shows an error alert when the application fails to load', async () => {
    getApplication.mockRejectedValueOnce(new Error('Application not found'));
    getApplicationVersions.mockResolvedValueOnce({ versions: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Application not found').length).toBeGreaterThan(0);
    });
  });

  it('shows the project repository path with an enabled edit button when no runs exist', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({ versions: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByTestId('project-path-value').length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText('/tmp/healthcare').length).toBeGreaterThan(0);

    const editEl = screen.getAllByTestId('edit-project-path')[0];
    const editBtn = editEl.tagName === 'BUTTON' ? editEl : editEl.querySelector('button');
    expect(editBtn).not.toBeNull();
    expect(editBtn.disabled).toBe(false);
  });

  it('disables the edit button once the app has at least one run', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({
      versions: [
        {
          id: 'v1',
          run_date: '2026-01-02T08:00:00Z',
          status: 'completed',
          threat_count: 4,
          high_severity_count: 1,
          categories: [],
        },
      ],
    });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByTestId('edit-project-path').length).toBeGreaterThan(0);
    });
    const editEl = screen.getAllByTestId('edit-project-path')[0];
    const editBtn = editEl.tagName === 'BUTTON' ? editEl : editEl.querySelector('button');
    expect(editBtn.disabled).toBe(true);
  });

  it('submits projectPath via updateApplication when path edit is saved', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    getApplicationVersions.mockResolvedValueOnce({ versions: [] });
    updateApplication.mockResolvedValueOnce({
      ...SAMPLE_APP,
      project_path: '/tmp/healthcare-v2',
    });

    renderPage();
    await waitFor(() => {
      expect(screen.getAllByTestId('edit-project-path').length).toBeGreaterThan(0);
    });
    const editEl = screen.getAllByTestId('edit-project-path')[0];
    const editBtn = editEl.tagName === 'BUTTON' ? editEl : editEl.querySelector('button');
    fireEvent.click(editBtn);

    await waitFor(() => {
      expect(screen.getAllByText('Edit project repository').length).toBeGreaterThan(0);
    });

    const testidEls = screen.getAllByTestId('project-path-input');
    const pathInput = testidEls[0].querySelector('input') || testidEls[0];
    fireEvent.change(pathInput, { target: { value: '/tmp/healthcare-v2' } });

    const saveEl = screen.getAllByTestId('save-project-path')[0];
    const saveBtn = saveEl.tagName === 'BUTTON' ? saveEl : saveEl.querySelector('button');
    fireEvent.click(saveBtn);
    await waitFor(() => {
      expect(updateApplication).toHaveBeenCalledWith('app_abc', {
        projectPath: '/tmp/healthcare-v2',
      });
    });
  });
});
