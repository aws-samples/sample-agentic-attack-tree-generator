import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import BusinessContextPanel from '../src/components/BusinessContextPanel.jsx';

vi.mock('../src/api-client', () => ({
  updateApplication: vi.fn(),
}));

import { updateApplication } from '../src/api-client';

const SAMPLE_CTX = {
  description: 'A healthcare intake API.',
  regulatory_frameworks: ['SOC2', 'HIPAA'],
  data_sensitivity: 'phi',
  main_cia_risk: 'confidentiality',
};

describe('BusinessContextPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('renders read-only view with the provided context', () => {
    render(<BusinessContextPanel appId="app_abc" businessContext={SAMPLE_CTX} />);
    expect(screen.getAllByText('A healthcare intake API.').length).toBeGreaterThan(0);
    expect(screen.getAllByText('SOC2').length).toBeGreaterThan(0);
    expect(screen.getAllByText('HIPAA').length).toBeGreaterThan(0);
    // Labels from the option lists (not raw literal values)
    expect(screen.getAllByText(/PHI — protected health information/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Confidentiality — leaks/).length).toBeGreaterThan(0);
  });

  it('renders em-dashes when fields are empty', () => {
    render(
      <BusinessContextPanel
        appId="app_abc"
        businessContext={{
          description: '',
          regulatory_frameworks: [],
          data_sensitivity: '',
          main_cia_risk: '',
        }}
      />
    );
    const dashes = screen.getAllByText('—');
    expect(dashes.length).toBeGreaterThanOrEqual(3);
  });

  it('opens the edit modal when the Edit button is clicked', async () => {
    render(<BusinessContextPanel appId="app_abc" businessContext={SAMPLE_CTX} />);
    fireEvent.click(screen.getAllByTestId('edit-business-context')[0]);
    await waitFor(() => {
      expect(screen.getAllByText('Edit business context').length).toBeGreaterThan(0);
    });
  });

  it('calls updateApplication with the draft when Save is clicked', async () => {
    updateApplication.mockResolvedValueOnce({
      id: 'app_abc',
      business_context: SAMPLE_CTX,
    });
    const onUpdated = vi.fn();
    render(
      <BusinessContextPanel
        appId="app_abc"
        businessContext={SAMPLE_CTX}
        onUpdated={onUpdated}
      />
    );
    fireEvent.click(screen.getAllByTestId('edit-business-context')[0]);
    await waitFor(() => {
      expect(screen.getAllByTestId('save-business-context').length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByTestId('save-business-context')[0]);
    await waitFor(() => {
      expect(updateApplication).toHaveBeenCalledWith('app_abc', {
        businessContext: expect.objectContaining({
          description: 'A healthcare intake API.',
          data_sensitivity: 'phi',
        }),
      });
    });
    expect(onUpdated).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'app_abc' })
    );
  });

  it('surfaces API errors as alerts without closing the modal', async () => {
    updateApplication.mockRejectedValueOnce(new Error('Server exploded'));
    render(<BusinessContextPanel appId="app_abc" businessContext={SAMPLE_CTX} />);
    fireEvent.click(screen.getAllByTestId('edit-business-context')[0]);
    await waitFor(() => {
      expect(screen.getAllByTestId('save-business-context').length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByTestId('save-business-context')[0]);
    await waitFor(() => {
      expect(screen.getAllByText('Server exploded').length).toBeGreaterThan(0);
    });
    // Modal still open
    expect(screen.getAllByText('Edit business context').length).toBeGreaterThan(0);
  });

  it('does not call updateApplication when the draft fails validation', async () => {
    render(
      <BusinessContextPanel
        appId="app_abc"
        businessContext={{
          description: '',
          regulatory_frameworks: [],
          data_sensitivity: '',
          main_cia_risk: '',
        }}
      />
    );
    fireEvent.click(screen.getAllByTestId('edit-business-context')[0]);
    await waitFor(() => {
      expect(screen.getAllByTestId('save-business-context').length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByTestId('save-business-context')[0]);
    // Give validation a tick to run
    await new Promise((r) => setTimeout(r, 0));
    expect(updateApplication).not.toHaveBeenCalled();
  });
});
