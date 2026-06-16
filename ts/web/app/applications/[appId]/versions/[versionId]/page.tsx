// Route: "/applications/:appId/versions/:versionId"  →  legacy ThreatModelSummaryPage
import ThreatModelSummaryView from './ThreatModelSummaryView.js';

export function generateStaticParams(): Array<{ appId: string; versionId: string }> {
  return [];
}

export default function ThreatModelSummaryRoute() {
  return <ThreatModelSummaryView />;
}
