'use client';

import { useParams } from 'next/navigation';
import PagePlaceholder from '../../../src/components/PagePlaceholder.js';

export default function AppOverviewView() {
  const params = useParams<{ appId: string }>();
  const appId = params.appId;
  return (
    <PagePlaceholder
      title="Application overview"
      description={`Versions and runs for application ${appId}.`}
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: appId, href: `/applications/${appId}` },
      ]}
      portsFrom={['pages/AppOverviewPage.jsx', 'components/VersionRowExportMenu.jsx']}
    />
  );
}
