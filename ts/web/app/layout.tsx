import type { Metadata } from 'next';
import type { ReactNode } from 'react';

// Cloudscape global styles. Importing the global stylesheet once at the root
// layout applies the design-system reset + typography to the whole app, mirroring
// the legacy SPA's top-level `@cloudscape-design/global-styles` import.
import '@cloudscape-design/global-styles/index.css';

export const metadata: Metadata = {
  title: 'ThreatForest',
  description: 'ThreatForest threat-modeling console.',
};

/**
 * Root layout for the app-router UI.
 *
 * The Cloudscape application shell (TopNavigation + AppLayout + SideNavigation)
 * lives in a separate client component ({@link AppShell}) because it relies on
 * `next/navigation` hooks; the root layout itself stays a server component and
 * only owns `<html>`/`<body>` and the global CSS import.
 */
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
