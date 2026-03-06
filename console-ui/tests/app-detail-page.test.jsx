import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AppDetailPage from '../src/pages/AppDetailPage.jsx';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../src/api-client', () => ({
  getApplicationVersions: vi.fn(),
}));

import { getApplicationVersions } from '../src/api-client';

function renderAppDetailPage(appId = 'test-app') {
  return render(
    <MemoryRouter initialEntries={[`/applications/${appId}`]}>
      <Routes>
        <Route path="/applications/:appId" element={<AppDetailPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('AppDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows spinner while loading', () => {
    getApplicationVersions.mockReturnValue(new Promise(() => {}));
    renderAppDetailPage();
    expect(screen.getAllByTestId('loading-spinner').length).toBeGreaterThan(0);
  });

  it('renders version table when data loads', async () => {
    getApplicationVersions.mockResolvedValue({
      versions: [
        {
          version_id: 'v1',
          run_date: '2024-06-01T10:00:00Z',
          status: 'completed',
          threat_count: 5,
        },
      ],
      application_name: 'My App',
    });
    renderAppDetailPage();
    await waitFor(() => {
      expect(screen.getAllByText('v1').length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText('Completed').length).toBeGreaterThan(0);
    expect(screen.getAllByText('5').length).toBeGreaterThan(0);
  });


  it('displays application name as header when returned by API', async () => {
    getApplicationVersions.mockResolvedValue({
      versions: [],
      application_name: 'My Cool App',
    });
    renderAppDetailPage();
    await waitFor(() => {
      expect(screen.getAllByText('My Cool App').length).toBeGreaterThan(0);
    });
  });

  it('falls back to appId when application_name is not in response', async () => {
    getApplicationVersions.mockResolvedValue({ versions: [] });
    renderAppDetailPage('fallback-id');
    await waitFor(() => {
      expect(screen.getAllByText('fallback-id').length).toBeGreaterThan(0);
    });
  });

  it('shows error alert when API call fails', async () => {
    getApplicationVersions.mockRejectedValue(new Error('Network error'));
    renderAppDetailPage();
    await waitFor(() => {
      expect(screen.getAllByText('Network error').length).toBeGreaterThan(0);
    });
  });

  it('shows empty state when no versions exist', async () => {
    getApplicationVersions.mockResolvedValue({ versions: [] });
    renderAppDetailPage();
    await waitFor(() => {
      expect(screen.getAllByText('No versions').length).toBeGreaterThan(0);
    });
  });

  it('renders status indicators correctly', async () => {
    getApplicationVersions.mockResolvedValue({
      versions: [
        { version_id: 'v1', run_date: '2024-01-01T00:00:00Z', status: 'completed', threat_count: 1 },
        { version_id: 'v2', run_date: '2024-02-01T00:00:00Z', status: 'failed', threat_count: 0 },
        { version_id: 'v3', run_date: '2024-03-01T00:00:00Z', status: 'in_progress', threat_count: 2 },
      ],
    });
    renderAppDetailPage();
    await waitFor(() => {
      expect(screen.getAllByText('Completed').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Failed').length).toBeGreaterThan(0);
      expect(screen.getAllByText('In progress').length).toBeGreaterThan(0);
    });
  });

  it('renders within CloudscapeShell with activePage="/applications"', async () => {
    getApplicationVersions.mockResolvedValue({ versions: [] });
    const { container } = renderAppDetailPage();
    await waitFor(() => {
      const activeLinks = container.querySelectorAll('[aria-current="page"]');
      expect(activeLinks.length).toBeGreaterThan(0);
      const hrefs = Array.from(activeLinks).map((el) => el.getAttribute('href'));
      expect(hrefs).toContain('/applications');
    });
  });

  it('renders breadcrumbs with Home, Applications, and app name', async () => {
    getApplicationVersions.mockResolvedValue({
      versions: [],
      application_name: 'Breadcrumb App',
    });
    renderAppDetailPage();
    await waitFor(() => {
      expect(screen.getAllByText('Breadcrumb App').length).toBeGreaterThan(0);
    });
    // Home and Applications should appear in breadcrumbs (and possibly nav)
    expect(screen.getAllByText('Home').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Applications').length).toBeGreaterThan(0);
  });

  it('calls getApplicationVersions with the correct appId', async () => {
    getApplicationVersions.mockResolvedValue({ versions: [] });
    renderAppDetailPage('my-app-123');
    await waitFor(() => {
      expect(getApplicationVersions).toHaveBeenCalledWith('my-app-123');
    });
  });
});