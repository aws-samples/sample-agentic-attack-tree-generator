// Route: "/applications/:appId/runs/new"  →  legacy NewRunPage (app-scoped variant)
import NewRunScopedView from './NewRunScopedView.js';

export function generateStaticParams(): Array<{ appId: string }> {
  return [];
}

export default function NewRunScopedRoute() {
  return <NewRunScopedView />;
}
