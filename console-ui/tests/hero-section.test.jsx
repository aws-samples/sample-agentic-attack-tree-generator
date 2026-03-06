import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import HeroSection from '../src/components/HeroSection.jsx';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

function renderHero() {
  return render(
    <MemoryRouter>
      <HeroSection />
    </MemoryRouter>
  );
}

describe('HeroSection', () => {
  beforeEach(() => {
    mockNavigate.mockClear();
  });

  it('renders the ThreatForest logo', () => {
    renderHero();
    const logos = screen.getAllByAltText('ThreatForest Logo');
    expect(logos.length).toBeGreaterThan(0);
    expect(logos[0].getAttribute('src')).toBe('/threatforest-logo.png');
  });

  it('renders the title', () => {
    renderHero();
    const titles = screen.getAllByText('ThreatForest');
    expect(titles.length).toBeGreaterThan(0);
  });

  it('renders the tagline', () => {
    renderHero();
    const taglines = screen.getAllByText(
      'AI-Driven Threat Modeling for Modern Applications'
    );
    expect(taglines.length).toBeGreaterThan(0);
  });

  it('renders the description', () => {
    renderHero();
    const descriptions = screen.getAllByText(
      /Automatically analyze your codebase/
    );
    expect(descriptions.length).toBeGreaterThan(0);
  });

  it('renders Start New Run button that navigates to /new-run', () => {
    renderHero();
    const buttons = screen.getAllByText('Start New Run');
    expect(buttons.length).toBeGreaterThan(0);
    // Click the actual button element (or its closest button ancestor)
    const btn = buttons[0].closest('button') || buttons[0];
    fireEvent.click(btn);
    expect(mockNavigate).toHaveBeenCalledWith('/new-run');
  });

  it('renders Browse Applications button that navigates to /applications', () => {
    renderHero();
    const buttons = screen.getAllByText('Browse Applications');
    expect(buttons.length).toBeGreaterThan(0);
    const btn = buttons[0].closest('button') || buttons[0];
    fireEvent.click(btn);
    expect(mockNavigate).toHaveBeenCalledWith('/applications');
  });

  it('renders all 6 pipeline stages', () => {
    renderHero();
    expect(screen.getAllByText('Repository Analysis').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Threat Parsing').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Attack Tree Generation').length).toBeGreaterThan(0);
    expect(screen.getAllByText('TTP Enrichment').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Mitigation Mapping').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Dashboard Generation').length).toBeGreaterThan(0);
  });

  it('renders the pipeline overview heading', () => {
    renderHero();
    const headings = screen.getAllByText('6-Stage AI Pipeline');
    expect(headings.length).toBeGreaterThan(0);
  });

  it('uses the hero-section CSS class', () => {
    const { container } = renderHero();
    expect(container.querySelector('.hero-section')).toBeTruthy();
  });
});
