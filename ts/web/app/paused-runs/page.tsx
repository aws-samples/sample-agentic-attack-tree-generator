'use client';

// Route: "/paused-runs"  →  legacy PausedRunsPage
import PagePlaceholder from '../../src/components/PagePlaceholder.js';

export default function PausedRunsRoute() {
  return (
    <PagePlaceholder
      title="Paused runs"
      description="Resume or discard runs paused mid-pipeline."
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Paused runs', href: '/paused-runs' },
      ]}
      portsFrom={['pages/PausedRunsPage.jsx']}
    />
  );
}
