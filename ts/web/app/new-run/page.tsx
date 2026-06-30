'use client';

// Route: "/new-run"  →  legacy NewRunPage (un-scoped variant; no appId in URL)
import NewRunView from '@/components/NewRunView';

export default function NewRunRoute() {
  return <NewRunView />;
}
