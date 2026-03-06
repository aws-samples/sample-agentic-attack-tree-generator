import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import HomePage, { PIPELINE_STAGES } from '../src/pages/HomePage.jsx';
import * as apiClient from '../src/api-client';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

function renderHomePage() {
  return render(
    <MemoryRouter>
      <HomePage />
    </MemoryRouter>
  );
}

describe('HomePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders ThreatForest branding (logo, product name, tagline, description)', () => {
    renderHomePage();
    // Logo with alt text
    const logos = screen.getAllByAltText('ThreatForest Logo');
    expect(logos.length).toBeGreaterThan(0);
    // Product name
    const names = screen.getAllByText('ThreatForest');
    expect(names.length).toBeGreaterThan(0);
    // Tagline
    expect(screen.getByText('AI-Driven Threat Modeling for Modern Applications')).toBeTruthy();
  });

  it('renders Get Started card with "Start New Run" button that navigates to /new-run', () => {
    renderHomePage();
    // "Get started" header
    const headers = screen.getAllByText(/Get started/i);
    expect(headers.length).toBeGreaterThan(0);
    // "Start New Run" button (Cloudscape may render multiple responsive copies)
    const buttons = screen.getAllByRole('button', { name: /start new run/i });
    expect(buttons.length).toBeGreaterThan(0);
    fireEvent.click(buttons[0]);
    expect(mockNavigate).toHaveBeenCalledWith('/new-run');
  });

  it('renders three Getting Started steps with correct text', () => {
    renderHomePage();
    // Cloudscape may render multiple responsive copies
    expect(screen.getAllByText('Step 1').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Step 2').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Step 3').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Configure credentials and model access').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Start run').length).toBeGreaterThan(0);
    expect(screen.getAllByText('View dashboard').length).toBeGreaterThan(0);
  });

  it('step buttons navigate to correct routes', () => {
    renderHomePage();
    const orangeBtns = document.querySelectorAll('.aws-orange-btn');
    expect(orangeBtns.length).toBeGreaterThanOrEqual(3);

    // Click the first three (one per step)
    fireEvent.click(orangeBtns[0]);
    expect(mockNavigate).toHaveBeenCalledWith('/configure');

    mockNavigate.mockClear();
    fireEvent.click(orangeBtns[1]);
    expect(mockNavigate).toHaveBeenCalledWith('/new-run');

    mockNavigate.mockClear();
    fireEvent.click(orangeBtns[2]);
    expect(mockNavigate).toHaveBeenCalledWith('/applications');
  });

  it('renders all six pipeline stage titles in How It Works section', () => {
    renderHomePage();
    const expectedTitles = [
      'Repository Analysis',
      'Threat Parsing',
      'Attack Tree Generation',
      'TTP Enrichment',
      'Mitigation Mapping',
      'Dashboard Generation',
    ];
    for (const title of expectedTitles) {
      expect(screen.getAllByText(title).length).toBeGreaterThan(0);
    }
    expect(PIPELINE_STAGES).toHaveLength(6);
  });

  it('renders within CloudscapeShell with activePage="/"', () => {
    const { container } = renderHomePage();
    // Verify the page renders within the shell (TopNavigation identity link)
    const identityLinks = container.querySelectorAll('a[href="/"]');
    expect(identityLinks.length).toBeGreaterThan(0);
  });

  it('does not call getApplications API', () => {
    const spy = vi.spyOn(apiClient, 'getApplications');
    renderHomePage();
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
