import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import AppLayout from '@cloudscape-design/components/app-layout';
import SideNavigation from '@cloudscape-design/components/side-navigation';
import BreadcrumbGroup from '@cloudscape-design/components/breadcrumb-group';

const NAV_ITEMS = [
  { type: 'link', text: 'Home', href: '/' },
  { type: 'link', text: 'New Run', href: '/new-run' },
  { type: 'link', text: 'Applications', href: '/applications' },
  { type: 'link', text: 'Configure', href: '/configure' },
];


export default function CloudscapeShell({ activePage, breadcrumbs, children, headerVariant, splitPanel, splitPanelOpen, onSplitPanelToggle, splitPanelPreferences, onSplitPanelPreferencesChange }) {
  const navigate = useNavigate();
  const [navOpen, setNavOpen] = useState(false);

  const handleNavFollow = (e) => {
    e.preventDefault();
    navigate(e.detail.href);
  };

  const handleBreadcrumbFollow = (e) => {
    e.preventDefault();
    navigate(e.detail.href);
  };

  return (
    <>
      <TopNavigation
        identity={{
          href: '/',
          title: 'ThreatForest',
          logo: {
            src: '/threatforest-logo.png',
            alt: 'ThreatForest Logo',
          },
        }}
        utilities={[]}
        onFollow={(e) => {
          e.preventDefault();
          const href = e.detail.href;
          if (href) navigate(href);
        }}
      />
      <AppLayout
        headerVariant={headerVariant || 'default'}
        navigationOpen={navOpen}
        onNavigationChange={({ detail }) => setNavOpen(detail.open)}
        navigation={
          <SideNavigation
            activeHref={activePage}
            items={NAV_ITEMS}
            onFollow={handleNavFollow}
          />
        }
        breadcrumbs={
          breadcrumbs && breadcrumbs.length > 0 ? (
            <BreadcrumbGroup
              items={breadcrumbs}
              onFollow={handleBreadcrumbFollow}
            />
          ) : null
        }
        content={children}
        splitPanel={splitPanel || null}
        splitPanelOpen={splitPanelOpen || false}
        onSplitPanelToggle={onSplitPanelToggle}
        splitPanelPreferences={splitPanelPreferences}
        onSplitPanelPreferencesChange={onSplitPanelPreferencesChange}
        toolsHide
      />
    </>
  );
}
