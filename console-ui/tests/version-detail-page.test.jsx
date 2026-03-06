import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import VersionDetailPage from '../src/pages/VersionDetailPage.jsx';

// Mock useParams to return appId and versionId
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

// Mock AttackTreeViewer since vis-network isn't available in jsdom
vi.mock('../src/components/AttackTreeViewer.jsx', () => ({
  default: ({ graphData }) => (
    <div data-testid="attack-tree-viewer">
      {graphData ? `nodes:${graphData.nodes.length},edges:${graphData.edges.length}` : 'no-data'}
    </div>
  ),
}));

const MOCK_VERSION_RESPONSE = {
  version_id: 'v1',
  run_date: '2024-06-01T10:00:00Z',
  status: 'completed',
  threat_count: 5,
  application_name: 'My App',
  attack_trees: [
    {
      name: 'Tree 1',
      mermaid: 'graph TD\n  A["Root"] --> B["Child"]',
    },
  ],
};

function renderVersionDetailPage(appId = 'app-1', versionId = 'v1') {
  return render(
    <MemoryRouter initialEntries={[`/applications/${appId}/versions/${versionId}`]}>
      <Routes>
        <Route
          path="/applications/:appId/versions/:versionId"
          element={<VersionDetailPage />}
        />
      </Routes>
    </MemoryRouter>
  );
}

describe('VersionDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn();
  });

  it('shows spinner while loading', () => {
    global.fetch.mockReturnValue(new Promise(() => {}));
    renderVersionDetailPage();
    expect(screen.getAllByTestId('loading-spinner').length).toBeGreaterThan(0);
  });

  it('renders version metadata after successful load', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => MOCK_VERSION_RESPONSE,
    });

    renderVersionDetailPage();

    await waitFor(() => {
      const versionIds = screen.getAllByTestId('meta-version-id');
      expect(versionIds.length).toBeGreaterThan(0);
    });

    expect(screen.getAllByTestId('meta-version-id')[0].textContent).toBe('v1');
    expect(screen.getAllByTestId('meta-run-date')[0].textContent).toBeTruthy();
    expect(screen.getAllByTestId('meta-status')[0].textContent).toContain('Completed');
  });

  it('renders AttackTreeViewer with parsed graph data', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => MOCK_VERSION_RESPONSE,
    });

    renderVersionDetailPage();

    await waitFor(() => {
      const viewers = screen.getAllByTestId('attack-tree-viewer');
      expect(viewers.length).toBeGreaterThan(0);
    });

    // The mermaid "A --> B" should produce 2 nodes and 1 edge
    expect(screen.getAllByTestId('attack-tree-viewer')[0].textContent).toBe('nodes:2,edges:1');
  });

  it('shows error alert when API call fails', async () => {
    global.fetch.mockResolvedValue({
      ok: false,
      status: 500,
    });

    renderVersionDetailPage();

    await waitFor(() => {
      const alerts = screen.getAllByText(/Failed to load version/);
      expect(alerts.length).toBeGreaterThan(0);
    });
  });

  it('shows error alert when fetch throws', async () => {
    global.fetch.mockRejectedValue(new Error('Network error'));

    renderVersionDetailPage();

    await waitFor(() => {
      const alerts = screen.getAllByText('Network error');
      expect(alerts.length).toBeGreaterThan(0);
    });
  });

  it('displays application name in breadcrumbs', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => MOCK_VERSION_RESPONSE,
    });

    renderVersionDetailPage('app-1', 'v1');

    await waitFor(() => {
      const versionIds = screen.getAllByTestId('meta-version-id');
      expect(versionIds.length).toBeGreaterThan(0);
    });

    // The breadcrumb should show the application name from the API response
    const appNameElements = screen.getAllByText('My App');
    expect(appNameElements.length).toBeGreaterThan(0);
  });

  it('displays version ID in page header', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => MOCK_VERSION_RESPONSE,
    });

    renderVersionDetailPage('app-1', 'v1');

    await waitFor(() => {
      const headers = screen.getAllByText('Version v1');
      expect(headers.length).toBeGreaterThan(0);
    });
  });

  it('handles version with no attack trees gracefully', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        ...MOCK_VERSION_RESPONSE,
        attack_trees: [],
      }),
    });

    renderVersionDetailPage();

    // Should still render metadata successfully even without attack trees
    await waitFor(() => {
      const versionIds = screen.getAllByTestId('meta-version-id');
      expect(versionIds.length).toBeGreaterThan(0);
      expect(versionIds[0].textContent).toBe('v1');
    });
  });

  it('renders status indicator for failed status', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        ...MOCK_VERSION_RESPONSE,
        status: 'failed',
      }),
    });

    renderVersionDetailPage();

    await waitFor(() => {
      const statusElements = screen.getAllByTestId('meta-status');
      const texts = statusElements.map((el) => el.textContent);
      expect(texts.some((t) => t.includes('Failed'))).toBe(true);
    });
  });

  it('renders status indicator for in_progress status', async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        ...MOCK_VERSION_RESPONSE,
        status: 'in_progress',
      }),
    });

    renderVersionDetailPage();

    await waitFor(() => {
      const statusElements = screen.getAllByTestId('meta-status');
      const texts = statusElements.map((el) => el.textContent);
      expect(texts.some((t) => t.includes('In progress'))).toBe(true);
    });
  });
});
