'use client';

// Both "/new-run" and "/applications/:appId/runs/new" render the legacy
// NewRunPage. This is the app-scoped entry point (appId is present in the URL);
// NewRunView reads the appId from next/navigation's useParams itself.
import NewRunView from '@/components/NewRunView';

export default function NewRunScopedView() {
  return <NewRunView />;
}
