'use client';

// Route: "/applications/new"  →  legacy CreateApplicationPage
// NOTE: this static "new" segment must resolve before the "[appId]" dynamic
// segment; Next.js app-router prefers literal segments over dynamic ones, so
// /applications/new will not be captured by /applications/[appId].
import PagePlaceholder from '../../../src/components/PagePlaceholder.js';

export default function CreateApplicationRoute() {
  return (
    <PagePlaceholder
      title="Create application"
      description="Register a new application for threat modeling."
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: 'New', href: '/applications/new' },
      ]}
      portsFrom={[
        'pages/CreateApplicationPage.jsx',
        'components/BusinessContextForm.jsx',
        'components/DirectoryPicker.jsx',
        'components/CiaPriorityList.jsx',
      ]}
    />
  );
}
