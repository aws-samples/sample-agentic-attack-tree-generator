// Route: "/runs/:runId/progress"  →  legacy RunProgressPage (wrapped keyed)
import RunProgressKeyedView from './RunProgressKeyedView.js';

export function generateStaticParams(): Array<{ runId: string }> {
  return [];
}

export default function RunProgressRoute() {
  return <RunProgressKeyedView />;
}
