'use client';

// Route: "/configure"  →  legacy ConfigurePage
import PagePlaceholder from '../../src/components/PagePlaceholder.js';

export default function ConfigureRoute() {
  return (
    <PagePlaceholder
      title="Configure"
      description="Model provider, embeddings, and Langfuse configuration."
      activePage="/configure"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Configure', href: '/configure' },
      ]}
      portsFrom={['pages/ConfigurePage.jsx']}
    />
  );
}
