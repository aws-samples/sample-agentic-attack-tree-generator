'use client';

// Route: "/"  →  legacy HomePage
import PagePlaceholder from '../src/components/PagePlaceholder.js';

export default function HomeRoute() {
  return (
    <PagePlaceholder
      title="ThreatForest"
      description="Threat-modeling console home."
      activePage="/"
      portsFrom={['pages/HomePage.jsx']}
    />
  );
}
