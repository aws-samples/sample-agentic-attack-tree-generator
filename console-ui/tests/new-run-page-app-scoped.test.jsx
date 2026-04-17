import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import NewRunPage from '../src/pages/NewRunPage.jsx';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../src/api-client', () => ({
  getApplication: vi.fn(),
  getConfig: vi.fn(),
  getFrameworks: vi.fn(),
  createRun: vi.fn(),
}));

import {
  getApplication,
  getConfig,
  getFrameworks,
  createRun,
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

const SAMPLE_FRAMEWORKS = {
  frameworks: {
    attack: { name: 'MITRE ATT&CK', description: 'Adversarial TTPs' },
    atlas: { name: 'MITRE ATLAS', description: 'ML system threats' },
    hipaa: { name: 'HIPAA', description: 'Healthcare compliance' },
  },
};

function renderAppScoped(appId = 'app_abc') {
  return render(
    <MemoryRouter initialEntries={[`/applications/${appId}/runs/new`]}>
      <Routes>
        <Route path="/applications/:appId/runs/new" element={<NewRunPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('NewRunPage (app-scoped)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getConfig.mockResolvedValue({
      model_provider: 'bedrock',
      model_id: 'claude-sonnet',
      embeddings_model: 'attack-bert',
      default_browse_path: '/',
    });
    getFrameworks.mockResolvedValue(SAMPLE_FRAMEWORKS);
  });

  afterEach(() => {
    cleanup();
  });

  it('shows a spinner while loading the application', () => {
    getApplication.mockReturnValue(new Promise(() => {}));
    renderAppScoped();
    expect(screen.getAllByTestId('loading-spinner').length).toBeGreaterThan(0);
  });

  it('locks the project path to the application value', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    renderAppScoped();
    await waitFor(() => {
      expect(screen.getAllByText('Project Path').length).toBeGreaterThan(0);
    });
    // The project path input is disabled; its value reflects the app path.
    const inputs = document.querySelectorAll('input[disabled]');
    const found = Array.from(inputs).some(
      (el) => el.value === '/tmp/healthcare'
    );
    expect(found).toBe(true);
  });

  it('submits with app_id and only selected frameworks', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    createRun.mockResolvedValueOnce({ run_id: 'run_123' });
    renderAppScoped();

    await waitFor(() => {
      expect(screen.getAllByText('Project Path').length).toBeGreaterThan(0);
    });

    // Walk through the wizard: Next → Next → Next → Submit
    const clickNext = async () => {
      const nextButtons = screen.getAllByText('Next');
      fireEvent.click(nextButtons[nextButtons.length - 1]);
    };
    await clickNext(); // Path → Threat source
    await waitFor(() =>
      expect(screen.getAllByText('Threat Statements').length).toBeGreaterThan(0)
    );
    await clickNext(); // Threat source → Frameworks
    await waitFor(() =>
      expect(screen.getAllByText('Threat Frameworks').length).toBeGreaterThan(0)
    );
    await clickNext(); // Frameworks → Review
    await waitFor(() =>
      expect(screen.getAllByText('Review & Confirm').length).toBeGreaterThan(0)
    );

    // Submit
    const submitButtons = screen.getAllByText('Submit');
    fireEvent.click(submitButtons[submitButtons.length - 1]);

    await waitFor(() => {
      expect(createRun).toHaveBeenCalled();
    });

    const submittedParams = createRun.mock.calls[0][0];
    expect(submittedParams.app_id).toBe('app_abc');
    expect(submittedParams.project_path).toBe('/tmp/healthcare');
    expect(submittedParams.threat_source).toBe('auto');
    // At least one framework should have been submitted (preselection set HIPAA).
    expect(Array.isArray(submittedParams.frameworks)).toBe(true);
    expect(submittedParams.frameworks).toContain('hipaa');
  });

  it('navigates to the app overview on cancel', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    renderAppScoped();
    await waitFor(() => {
      expect(screen.getAllByText('Cancel').length).toBeGreaterThan(0);
    });
    const cancelButtons = screen.getAllByText('Cancel');
    fireEvent.click(cancelButtons[cancelButtons.length - 1]);
    expect(mockNavigate).toHaveBeenCalledWith('/applications/app_abc');
  });

  it('surfaces an error when the application fails to load', async () => {
    getApplication.mockRejectedValueOnce(new Error('Application not found'));
    renderAppScoped();
    await waitFor(() => {
      expect(screen.getAllByText('Application not found').length).toBeGreaterThan(0);
    });
  });

  it('preselects only frameworks matching the business context', async () => {
    getApplication.mockResolvedValueOnce(SAMPLE_APP);
    renderAppScoped();

    // Advance to the Frameworks step.
    await waitFor(() => {
      expect(screen.getAllByText('Project Path').length).toBeGreaterThan(0);
    });
    const nextButtons1 = screen.getAllByText('Next');
    fireEvent.click(nextButtons1[nextButtons1.length - 1]);
    await waitFor(() =>
      expect(screen.getAllByText('Threat Statements').length).toBeGreaterThan(0)
    );
    const nextButtons2 = screen.getAllByText('Next');
    fireEvent.click(nextButtons2[nextButtons2.length - 1]);
    await waitFor(() =>
      expect(screen.getAllByText('Threat Frameworks').length).toBeGreaterThan(0)
    );

    // Verify preselection: exactly one of the three checkboxes should be
    // checked, because only HIPAA matches the business-context frameworks.
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');
    expect(checkboxes.length).toBe(3);
    const checkedCount = Array.from(checkboxes).filter((cb) => cb.checked).length;
    expect(checkedCount).toBe(1);
  });
});
