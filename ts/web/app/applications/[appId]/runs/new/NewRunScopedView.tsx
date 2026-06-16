'use client';

import { useParams } from 'next/navigation';
import PagePlaceholder from '../../../../../src/components/PagePlaceholder.js';

// Both "/new-run" and "/applications/:appId/runs/new" render the legacy
// NewRunPage. This is the app-scoped entry point (appId is present in the URL).
export default function NewRunScopedView() {
  const params = useParams<{ appId: string }>();
  const appId = params.appId;
  return (
    <PagePlaceholder
      title="New run"
      description={`Start a new threat-modeling run for application ${appId}.`}
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: appId, href: `/applications/${appId}` },
        { text: 'New run', href: `/applications/${appId}/runs/new` },
      ]}
      portsFrom={[
        'pages/NewRunPage.jsx',
        'components/DirectoryPicker.jsx',
        'components/BusinessContextPanel.jsx',
      ]}
    />
  );
}
