// Route: "/runs/:runId/progress"  →  legacy RunProgressPage (wrapped keyed)
import RunProgressKeyedView from './RunProgressKeyedView';

export function generateStaticParams(): Array<{ runId: string }> {
  return [{ runId: '__shell__' }];
}

export default function RunProgressRoute() {
  return <RunProgressKeyedView />;
}
