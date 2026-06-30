'use client';

/**
 * Route "/" — the applications list is the landing page.
 *
 * Previously this was a marketing landing page (hero + "How ThreatForest works"
 * explainer + a single context-aware CTA) that never showed the apps list. Per
 * product direction the home page now IS the applications view; the shared
 * ApplicationsView renders the same table used at /applications, with the
 * active/paused-run banners surfaced here so the run-resumption affordances
 * from the old landing page are preserved.
 */

import ApplicationsView from '@/components/ApplicationsView';

export default function HomePage() {
  return (
    <ApplicationsView
      activePage="/"
      breadcrumbs={[{ text: 'Applications', href: '/' }]}
      showRunBanners
    />
  );
}
