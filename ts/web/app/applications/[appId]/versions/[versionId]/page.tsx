// Route: "/applications/:appId/versions/:versionId"  →  legacy ThreatModelSummaryPage
import { Suspense } from 'react';
import ThreatModelSummaryView from './ThreatModelSummaryView';

export function generateStaticParams(): Array<{ appId: string; versionId: string }> {
  return [{ appId: '__shell__', versionId: '__shell__' }];
}

export default function ThreatModelSummaryRoute() {
  // ThreatModelSummaryView calls useSearchParams(); under output:'export' any
  // client component reading search params must sit inside a Suspense boundary
  // (Next's CSR-bailout requirement for static prerender).
  return (
    <Suspense fallback={null}>
      <ThreatModelSummaryView />
    </Suspense>
  );
}
