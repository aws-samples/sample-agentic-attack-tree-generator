'use client';

/**
 * Cloudscape application shell — TS/Next port of console-ui's CloudscapeShell.jsx.
 *
 * The legacy component used react-router's `useNavigate`; here we use Next's
 * `useRouter().push`. The public props are otherwise the same so page ports can
 * adopt this with minimal churn.
 */

import { useState, type ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import AppLayout from '@cloudscape-design/components/app-layout';
import SideNavigation from '@cloudscape-design/components/side-navigation';
import BreadcrumbGroup from '@cloudscape-design/components/breadcrumb-group';
import type { AppLayoutProps } from '@cloudscape-design/components/app-layout';
import type { SideNavigationProps } from '@cloudscape-design/components/side-navigation';
import type { BreadcrumbGroupProps } from '@cloudscape-design/components/breadcrumb-group';

const NAV_ITEMS: ReadonlyArray<SideNavigationProps.Item> = [
  { type: 'link', text: 'Home', href: '/' },
  { type: 'link', text: 'Applications', href: '/applications' },
  { type: 'link', text: 'Configure', href: '/configure' },
];

export interface AppShellProps {
  /** Active side-nav href used to highlight the current section. */
  activePage?: string;
  /** Breadcrumb items rendered above the content. */
  breadcrumbs?: BreadcrumbGroupProps.Item[];
  children?: ReactNode;
  headerVariant?: AppLayoutProps['headerVariant'];
  splitPanel?: ReactNode;
  splitPanelOpen?: boolean;
  onSplitPanelToggle?: AppLayoutProps['onSplitPanelToggle'];
  splitPanelPreferences?: AppLayoutProps['splitPanelPreferences'];
  onSplitPanelPreferencesChange?: AppLayoutProps['onSplitPanelPreferencesChange'];
}

export default function AppShell({
  activePage,
  breadcrumbs,
  children,
  headerVariant,
  splitPanel,
  splitPanelOpen,
  onSplitPanelToggle,
  splitPanelPreferences,
  onSplitPanelPreferencesChange,
}: AppShellProps) {
  const router = useRouter();
  const [navOpen, setNavOpen] = useState(false);

  const handleNavFollow: SideNavigationProps['onFollow'] = (e) => {
    e.preventDefault();
    router.push(e.detail.href);
  };

  const handleBreadcrumbFollow: BreadcrumbGroupProps['onFollow'] = (e) => {
    e.preventDefault();
    router.push(e.detail.href);
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
          onFollow: (e) => {
            e.preventDefault();
            router.push('/');
          },
        }}
        utilities={[]}
      />
      <AppLayout
        headerVariant={headerVariant || 'default'}
        navigationOpen={navOpen}
        onNavigationChange={({ detail }) => setNavOpen(detail.open)}
        navigation={
          <SideNavigation
            activeHref={activePage}
            items={[...NAV_ITEMS]}
            onFollow={handleNavFollow}
          />
        }
        breadcrumbs={
          breadcrumbs && breadcrumbs.length > 0 ? (
            <BreadcrumbGroup items={breadcrumbs} onFollow={handleBreadcrumbFollow} />
          ) : undefined
        }
        content={children}
        splitPanel={splitPanel ?? undefined}
        splitPanelOpen={splitPanelOpen || false}
        onSplitPanelToggle={onSplitPanelToggle}
        splitPanelPreferences={splitPanelPreferences}
        onSplitPanelPreferencesChange={onSplitPanelPreferencesChange}
        toolsHide
      />
    </>
  );
}
