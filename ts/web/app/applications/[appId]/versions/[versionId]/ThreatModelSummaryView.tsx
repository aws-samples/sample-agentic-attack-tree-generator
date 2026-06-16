'use client';

import { useParams } from 'next/navigation';
import PagePlaceholder from '../../../../../src/components/PagePlaceholder.js';

export default function ThreatModelSummaryView() {
  const params = useParams<{ appId: string; versionId: string }>();
  const { appId, versionId } = params;
  return (
    <PagePlaceholder
      title="Threat model summary"
      description={`Threats and mitigations for version ${versionId}.`}
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: appId, href: `/applications/${appId}` },
        { text: versionId, href: `/applications/${appId}/versions/${versionId}` },
      ]}
      portsFrom={[
        'pages/ThreatModelSummaryPage.jsx',
        'components/MitigationsTable.jsx',
        'components/ExportButton.jsx',
        'components/CustomiseExportModal.jsx',
      ]}
    />
  );
}
