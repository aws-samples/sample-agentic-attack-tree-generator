'use client';

import { useParams } from 'next/navigation';
import PagePlaceholder from '../../../../src/components/PagePlaceholder.js';

/**
 * Inner page body for a single run's live progress.
 *
 * Kept as a separate component so the keyed wrapper below can force a full
 * remount when `runId` changes. The legacy SPA did this with React Router's
 * `<RunProgressPage key={runId} />` to stop run-scoped state (controlPending,
 * scanStatus) from bleeding across runs after a Resume navigates to a new id.
 */
function RunProgressBody({ runId }: { runId: string }) {
  return (
    <PagePlaceholder
      title="Run progress"
      description={`Live pipeline progress for run ${runId}.`}
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Run progress', href: `/runs/${runId}/progress` },
      ]}
      portsFrom={[
        'pages/RunProgressPage.jsx',
        'components/StageCard.jsx',
        'components/ActivityFeed.jsx',
        'components/InterviewerPanel.jsx',
        'components/ScannerReviewPanel.jsx',
        'components/ThreatReviewPanel.jsx',
      ]}
    />
  );
}

export default function RunProgressKeyedView() {
  const params = useParams<{ runId: string }>();
  const runId = params.runId;
  // `key={runId}` forces a fresh component instance per run id, matching the
  // legacy RunProgressPageKeyed remount behavior.
  return <RunProgressBody key={runId} runId={runId} />;
}
