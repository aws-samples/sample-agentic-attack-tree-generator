'use client';

import { useParams } from 'next/navigation';
import PagePlaceholder from '../../../../../../../src/components/PagePlaceholder.js';

export default function VersionDetailView() {
  const params = useParams<{ appId: string; versionId: string; threatIndex: string }>();
  const { appId, versionId, threatIndex } = params;
  return (
    <PagePlaceholder
      title="Threat detail"
      description={`Attack tree for threat #${threatIndex} in version ${versionId}.`}
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: appId, href: `/applications/${appId}` },
        { text: versionId, href: `/applications/${appId}/versions/${versionId}` },
        {
          text: `Threat ${threatIndex}`,
          href: `/applications/${appId}/versions/${versionId}/threats/${threatIndex}`,
        },
      ]}
      portsFrom={[
        'pages/VersionDetailPage.jsx',
        'components/ReactFlowAttackTreeViewer.jsx',
        'components/AttackFlowViewer.jsx',
        'components/AttackTreeNode.jsx',
        'components/ActionNode.jsx',
        'components/NodeDetailPanel.jsx',
        'components/PropertiesPanel.jsx',
        'components/MitigationStatusEditor.jsx',
      ]}
    />
  );
}
