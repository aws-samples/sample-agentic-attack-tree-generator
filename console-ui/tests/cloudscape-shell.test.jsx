import { describe, it, expect } from 'vitest';
import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import CloudscapeShell from '../src/components/CloudscapeShell.jsx';

function renderShell(props = {}) {
  const defaults = {
    activePage: '/',
    breadcrumbs: [],
    children: <div data-testid="page-content">Page Content</div>,
  };
  return render(
    <MemoryRouter>
      <CloudscapeShell {...defaults} {...props} />
    </MemoryRouter>
  );
}

describe('CloudscapeShell', () => {
  it('renders children in the content area', () => {
    renderShell();
    // Cloudscape AppLayout may render content in multiple responsive slots
    const contents = screen.getAllByTestId('page-content');
    expect(contents.length).toBeGreaterThan(0);
    expect(contents[0].textContent).toBe('Page Content');
  });

  it('renders the ThreatForest title in TopNavigation', () => {
    renderShell();
    // TopNavigation renders title in multiple responsive breakpoints
    const titles = screen.getAllByText('ThreatForest');
    expect(titles.length).toBeGreaterThan(0);
  });

  it('renders the ThreatForest logo', () => {
    renderShell();
    const logos = screen.getAllByAltText('ThreatForest Logo');
    expect(logos.length).toBeGreaterThan(0);
    expect(logos[0].getAttribute('src')).toBe('/threatforest-logo.png');
  });

  it('renders SideNavigation with all four nav items', () => {
    renderShell();
    // Each nav label appears in both TopNavigation utilities and SideNavigation
    expect(screen.getAllByText('Home').length).toBeGreaterThan(0);
    expect(screen.getAllByText('New Run').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Applications').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Configure').length).toBeGreaterThan(0);
  });

  it('renders breadcrumbs when provided', () => {
    renderShell({
      breadcrumbs: [
        { text: 'Home', href: '/' },
        { text: 'My Apps', href: '/applications' },
      ],
    });
    // "My Apps" is unique to breadcrumbs (not in nav items)
    const breadcrumbItems = screen.getAllByText('My Apps');
    expect(breadcrumbItems.length).toBeGreaterThan(0);
  });

  it('highlights the active SideNavigation item based on activePage prop', () => {
    const { container } = renderShell({ activePage: '/applications' });
    // Cloudscape SideNavigation marks the active item with an aria-current attribute
    const activeLinks = container.querySelectorAll('[aria-current="page"]');
    expect(activeLinks.length).toBeGreaterThan(0);
    // The active link should point to /applications
    const hrefs = Array.from(activeLinks).map((el) => el.getAttribute('href'));
    expect(hrefs).toContain('/applications');
  });
});
