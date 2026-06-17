'use client';

/**
 * Route "/applications" — applications list.
 *
 * Thin wrapper over the shared ApplicationsView (also rendered at "/"). The
 * table, sorting, per-row export, and delete logic live in the shared
 * component; this route only supplies its own nav highlight + breadcrumbs and
 * omits the run banners (those are surfaced on the home variant).
 */

import ApplicationsView from '@/components/ApplicationsView';

export default function ApplicationsPage() {
  return (
    <ApplicationsView
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
      ]}
    />
  );
}
