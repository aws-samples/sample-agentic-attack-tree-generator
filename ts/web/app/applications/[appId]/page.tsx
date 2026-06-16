// Route: "/applications/:appId"  →  legacy AppOverviewPage
//
// Server component: owns `generateStaticParams` (required for `output: 'export'`
// on a dynamic route). The actual page is a client component that reads the
// `appId` param at runtime via `useParams()`. We return [] here because the set
// of application ids is not known at build time — the UI is client-navigated.
import AppOverviewView from './AppOverviewView.js';

export function generateStaticParams(): Array<{ appId: string }> {
  return [];
}

export default function AppOverviewRoute() {
  return <AppOverviewView />;
}
