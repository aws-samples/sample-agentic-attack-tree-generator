'use client';

// Route: "/new-run"  →  legacy NewRunPage (un-scoped variant; no appId in URL)
import PagePlaceholder from '../../src/components/PagePlaceholder.js';

export default function NewRunRoute() {
  return (
    <PagePlaceholder
      title="New run"
      description="Start a new threat-modeling run."
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'New run', href: '/new-run' },
      ]}
      portsFrom={[
        'pages/NewRunPage.jsx',
        'components/DirectoryPicker.jsx',
        'components/BusinessContextPanel.jsx',
      ]}
    />
  );
}
