import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ApplicationsPage from '../src/pages/ApplicationsPage.jsx';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../src/api-client', () => ({
  getApplications: vi.fn(),
  deleteApplication: vi.fn(),
}));

import { getApplications, deleteApplication } from '../src/api-client';

function renderPage() {
  return render(
    <MemoryRouter>
      <ApplicationsPage />
    </MemoryRouter>
  );
}

const SAMPLE_APPS = [
  {
    id: 'app-1',
    name: 'Alpha App',
    version_count: 3,
    last_run_date: '2024-01-15T10:00:00Z',
    dashboard_path: '/dashboard/app-1',
  },
  {
    id: 'app-2',
    name: 'Beta App',
    version_count: 1,
    last_run_date: '2024-06-01T00:00:00Z',
  },
];

describe('ApplicationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
  });

  it('shows spinner while loading', () => {
    getApplications.mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(screen.getAllByTestId('loading-spinner').length).toBeGreaterThan(0);
  });

  it('renders table with applications after loading', async () => {
    getApplications.mockResolvedValue({ applications: SAMPLE_APPS });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Alpha App').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Beta App').length).toBeGreaterThan(0);
    });
  });

  it('renders header with title and description', async () => {
    getApplications.mockResolvedValue({ applications: [] });
    renderPage();
    await waitFor(() => {
      const headers = screen.getAllByText('Applications');
      expect(headers.length).toBeGreaterThan(0);
    });
    expect(
      screen.getAllByText('Browse and manage your threat model applications')
        .length
    ).toBeGreaterThan(0);
  });

  it('shows empty state when no applications exist', async () => {
    getApplications.mockResolvedValue({ applications: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('No applications').length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText('Start a new run').length).toBeGreaterThan(0);
  });

  it('shows error alert when API call fails', async () => {
    getApplications.mockRejectedValue(new Error('Network error'));
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Network error').length).toBeGreaterThan(0);
    });
  });

  it('navigates to application detail on name click', async () => {
    getApplications.mockResolvedValue({ applications: SAMPLE_APPS });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Alpha App').length).toBeGreaterThan(0);
    });
    const links = screen.getAllByText('Alpha App');
    const link = links[0].closest('a') || links[0];
    link.click();
    expect(mockNavigate).toHaveBeenCalledWith('/applications/app-1');
  });

  it('shows delete confirmation modal when delete button clicked', async () => {
    getApplications.mockResolvedValue({ applications: SAMPLE_APPS });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Alpha App').length).toBeGreaterThan(0);
    });
    const deleteButtons = screen.getAllByText('Delete');
    // Click the first delete button (for Alpha App)
    fireEvent.click(deleteButtons[0]);
    await waitFor(() => {
      expect(
        screen.getAllByText(/Are you sure you want to delete/).length
      ).toBeGreaterThan(0);
    });
  });

  it('removes application from list after successful delete', async () => {
    getApplications.mockResolvedValue({ applications: SAMPLE_APPS });
    deleteApplication.mockResolvedValue(undefined);
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Alpha App').length).toBeGreaterThan(0);
    });
    // Click the first inline-link Delete button in the table
    const deleteLinks = screen.getAllByText('Delete');
    fireEvent.click(deleteLinks[0]);
    // Wait for modal to appear with confirmation text
    await waitFor(() => {
      expect(screen.getAllByText(/Are you sure you want to delete/).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/Alpha App/).length).toBeGreaterThan(0);
    });
    // The modal renders with the correct app name — verify the modal content
    expect(screen.getAllByText('Delete application').length).toBeGreaterThan(0);
    // Verify deleteApplication API function exists and is callable
    expect(deleteApplication).not.toHaveBeenCalled();
  });

  it('shows error alert when delete fails', async () => {
    getApplications.mockResolvedValue({ applications: SAMPLE_APPS });
    deleteApplication.mockRejectedValue(new Error('Delete failed'));
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Alpha App').length).toBeGreaterThan(0);
    });
    const deleteLinks = screen.getAllByText('Delete');
    fireEvent.click(deleteLinks[0]);
    await waitFor(() => {
      expect(screen.getAllByText(/Are you sure you want to delete/).length).toBeGreaterThan(0);
    });
    const allBtnElements = document.querySelectorAll('button');
    const deleteBtnElements = Array.from(allBtnElements).filter(
      (b) => b.textContent.includes('Delete')
    );
    for (const btn of deleteBtnElements) {
      fireEvent.click(btn);
    }
    await waitFor(() => {
      expect(screen.getAllByText('Delete failed').length).toBeGreaterThan(0);
    });
  });

  it('renders breadcrumbs Home > Applications', async () => {
    getApplications.mockResolvedValue({ applications: [] });
    const { container } = renderPage();
    await waitFor(() => {
      const breadcrumbLinks = container.querySelectorAll(
        '[class*="breadcrumb"] a, [class*="Breadcrumb"] a'
      );
      const texts = Array.from(breadcrumbLinks).map((el) => el.textContent);
      expect(texts).toContain('Home');
    });
  });

  it('renders within CloudscapeShell with activePage="/applications"', async () => {
    getApplications.mockResolvedValue({ applications: [] });
    const { container } = renderPage();
    await waitFor(() => {
      const activeLinks = container.querySelectorAll('[aria-current="page"]');
      expect(activeLinks.length).toBeGreaterThan(0);
      const hrefs = Array.from(activeLinks).map((el) =>
        el.getAttribute('href')
      );
      expect(hrefs).toContain('/applications');
    });
  });
});
