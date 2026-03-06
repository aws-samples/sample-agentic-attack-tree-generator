import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import NewRunPage from '../src/pages/NewRunPage.jsx';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../src/api-client', () => ({
  getConfig: vi.fn(),
  createRun: vi.fn(),
}));

import { getConfig, createRun } from '../src/api-client';

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/new-run']}>
      <NewRunPage />
    </MemoryRouter>
  );
}

/** Helper: type into a Cloudscape Input by finding its native <input> and firing events */
function typeIntoInput(placeholder, value) {
  const inputs = screen.getAllByPlaceholderText(placeholder);
  const nativeInput = inputs[0];
  // Cloudscape Input listens on the native input's 'input' event
  fireEvent.input(nativeInput, { target: { value } });
}

/** Helper: click the wizard Next button */
function clickNext() {
  const buttons = screen.getAllByRole('button');
  const nextBtn = buttons.find((b) => b.textContent.trim() === 'Next');
  if (nextBtn) fireEvent.click(nextBtn);
}

/** Helper: click the wizard Submit button */
function clickSubmit() {
  const buttons = screen.getAllByRole('button');
  const submitBtn = buttons.find((b) => b.textContent.trim() === 'Submit');
  if (submitBtn) fireEvent.click(submitBtn);
}

describe('NewRunPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getConfig.mockResolvedValue({ model_provider: 'bedrock', model_id: 'claude-v3' });
  });

  it('renders within CloudscapeShell with activePage="/new-run"', async () => {
    const { container } = renderPage();
    await waitFor(() => {
      const activeLinks = container.querySelectorAll('[aria-current="page"]');
      expect(activeLinks.length).toBeGreaterThan(0);
      const hrefs = Array.from(activeLinks).map((el) => el.getAttribute('href'));
      expect(hrefs).toContain('/new-run');
    });
  });

  it('renders wizard with Project Path step visible', () => {
    renderPage();
    expect(screen.getAllByText('Project Path').length).toBeGreaterThan(0);
  });

  it('renders project path input field', () => {
    renderPage();
    const inputs = screen.getAllByPlaceholderText('/path/to/project');
    expect(inputs.length).toBeGreaterThan(0);
  });

  it('validates project path is not empty before advancing', async () => {
    renderPage();
    clickNext();
    await waitFor(() => {
      expect(screen.getAllByText('Project path is required.').length).toBeGreaterThan(0);
    });
  });

  it('shows radio options after navigating to step 2', async () => {
    renderPage();
    typeIntoInput('/path/to/project', '/my/project');
    clickNext();
    await waitFor(() => {
      expect(screen.getAllByText('Auto-generate using AI').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Provide existing threat statements file').length).toBeGreaterThan(0);
    });
  });

  it('shows review with config data after navigating to step 3', async () => {
    getConfig.mockResolvedValue({ model_provider: 'bedrock', model_id: 'claude-v3' });
    renderPage();

    typeIntoInput('/path/to/project', '/my/project');
    clickNext();

    await waitFor(() => {
      expect(screen.getAllByText('Auto-generate using AI').length).toBeGreaterThan(0);
    });
    clickNext();

    await waitFor(() => {
      expect(screen.getAllByText('bedrock').length).toBeGreaterThan(0);
      expect(screen.getAllByText('claude-v3').length).toBeGreaterThan(0);
    });
  });

  it('displays key-value labels in review step', async () => {
    renderPage();

    typeIntoInput('/path/to/project', '/my/project');
    clickNext();

    await waitFor(() => {
      expect(screen.getAllByText('Auto-generate using AI').length).toBeGreaterThan(0);
    });
    clickNext();

    await waitFor(() => {
      expect(screen.getAllByText('Model provider').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Model ID').length).toBeGreaterThan(0);
    });
  });

  it('submits run and navigates on success', async () => {
    createRun.mockResolvedValue({ run_id: 'run-123' });
    renderPage();

    // Type project path
    typeIntoInput('/path/to/project', '/my/project');

    // Navigate to step 3 by setting active step directly via wizard
    // Since Cloudscape Wizard validates on navigate, we need the state to be valid
    // Click Next to go to step 2
    clickNext();

    await waitFor(() => {
      // Step 2 should be navigable — check that radio group is present
      const radios = screen.getAllByText('Auto-generate using AI');
      expect(radios.length).toBeGreaterThan(0);
    });

    // Click Next to go to step 3
    clickNext();

    await waitFor(() => {
      const reviewHeaders = screen.getAllByText('Review & Confirm');
      expect(reviewHeaders.length).toBeGreaterThan(0);
    });

    // Click Submit
    clickSubmit();

    await waitFor(() => {
      expect(createRun).toHaveBeenCalledWith({
        project_path: '/my/project',
        threat_source: 'auto',
      });
      expect(mockNavigate).toHaveBeenCalledWith('/runs/run-123/progress');
    });
  });

  it('shows error alert when submission fails', async () => {
    createRun.mockRejectedValue(new Error('Server error'));
    renderPage();

    typeIntoInput('/path/to/project', '/my/project');
    clickNext();

    await waitFor(() => {
      expect(screen.getAllByText('Auto-generate using AI').length).toBeGreaterThan(0);
    });

    clickNext();

    await waitFor(() => {
      expect(screen.getAllByText('Review & Confirm').length).toBeGreaterThan(0);
    });

    clickSubmit();

    await waitFor(() => {
      expect(screen.getAllByText('Server error').length).toBeGreaterThan(0);
    });
  });

  it('navigates home on cancel', () => {
    renderPage();
    const buttons = screen.getAllByRole('button');
    const cancelBtn = buttons.find((b) => b.textContent.trim() === 'Cancel');
    if (cancelBtn) fireEvent.click(cancelBtn);
    expect(mockNavigate).toHaveBeenCalledWith('/');
  });

  it('renders breadcrumbs with Home and New Run', async () => {
    const { container } = renderPage();
    await waitFor(() => {
      const breadcrumbLinks = container.querySelectorAll(
        '[class*="breadcrumb"] a, [class*="Breadcrumb"] a'
      );
      const texts = Array.from(breadcrumbLinks).map((el) => el.textContent);
      expect(texts).toContain('Home');
    });
  });

  it('fetches config on mount', async () => {
    renderPage();
    await waitFor(() => {
      expect(getConfig).toHaveBeenCalledTimes(1);
    });
  });
});
