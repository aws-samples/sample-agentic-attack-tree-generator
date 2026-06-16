'use client';

// Route: "/applications"  →  legacy ApplicationsPage
import PagePlaceholder from '../../src/components/PagePlaceholder.js';

export default function ApplicationsRoute() {
  return (
    <PagePlaceholder
      title="Applications"
      description="Browse threat-modeled applications and their versions."
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
      ]}
      portsFrom={['pages/ApplicationsPage.jsx', 'components/ImportReportButton.jsx']}
    />
  );
}
