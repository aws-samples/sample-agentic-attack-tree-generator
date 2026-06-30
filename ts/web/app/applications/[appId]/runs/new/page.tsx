// Route: "/applications/:appId/runs/new"  →  legacy NewRunPage (app-scoped variant)
import NewRunScopedView from './NewRunScopedView';

export function generateStaticParams(): Array<{ appId: string }> {
  return [{ appId: '__shell__' }];
}

export default function NewRunScopedRoute() {
  return <NewRunScopedView />;
}
