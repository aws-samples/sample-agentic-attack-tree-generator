'use client';

/**
 * RunProgressKeyedView — TS/Next port of console-ui's RunProgressPage.jsx,
 * plus the keyed remount wrapper the legacy SPA used.
 *
 * Live pipeline progress over a WebSocket: stage cards, activity feed, and the
 * three HITL panels (interviewer / scanner review / threat review).
 *
 * react-router (useParams/useNavigate) → next/navigation (useParams/useRouter).
 * CloudscapeShell → AppShell. The inner RunProgressBody is re-mounted via
 * `key={runId}` so run-scoped state (scanStatus, controlPending, …) doesn't
 * bleed across runs after a Resume navigates to a new id — matching the legacy
 * `<RunProgressPage key={runId} />`.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useRealParams } from '@/hooks/useRealParams';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Alert from '@cloudscape-design/components/alert';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import Link from '@cloudscape-design/components/link';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import type { BreadcrumbGroupProps } from '@cloudscape-design/components/breadcrumb-group';
import AppShell from '@/components/AppShell';
import StageCard, { type StageStatus, type ThreatProgress, type StageWorker } from '@/components/StageCard';
import ActivityFeed, { type ActivityEntry, type ActivityEntryType } from '@/components/ActivityFeed';
import InterviewerPanel, { type InterviewerChatEntry } from '@/components/InterviewerPanel';
import ThreatReviewPanel, { type ReviewThreat, type ThreatReviewApply } from '@/components/ThreatReviewPanel';
import type { ScannerData, ScannerReviewEdits } from '@/components/ScannerReviewPanel';
import {
  connectRunWebSocket,
  pauseRun,
  stopRun,
  resumeRun,
  submitRunResponse,
  getRun,
  getApplication,
  type RunWebSocketController,
} from '@/api/client';

const STAGES = [
  'Repository Analysis',
  'Context Validation',
  'Threat Generation',
  'Threat Review',
  'Parallel Analysis',
  'Dashboard Generation',
] as const;

const stageIndexMap: Record<string, number> = {
  'Repository Analysis': 0,
  'Context Validation': 1,
  'Threat Generation': 2,
  'Threat Review': 3,
  'Parallel Analysis': 4,
  'Dashboard Generation': 5,
  // Fallback internal names
  setup: 0,
  context_analysis: 0,
  extraction: 0,
  tree_generation: 4,
  ttc_enrichment: 4,
  mitigation: 4,
  summary: 5,
};

function resolveStageIndex(stageName: string): number {
  if (stageName in stageIndexMap) return stageIndexMap[stageName]!;
  // Try case-insensitive match against STAGES
  const lower = stageName.toLowerCase();
  const idx = STAGES.findIndex((s) => s.toLowerCase() === lower);
  return idx >= 0 ? idx : -1;
}

function formatTimestamp(): string {
  return new Date().toLocaleTimeString();
}

interface StageState {
  name: string;
  status: StageStatus;
  progress: number;
  statusText: string;
  startTime: number | null;
  endTime: number | null;
  threatProgress: ThreatProgress | null;
  errorMessage: string | null;
  workers: StageWorker[] | null;
  findings?: string[] | null;
}

const INITIAL_STAGES: StageState[] = STAGES.map((name) => ({
  name,
  status: 'pending',
  progress: 0,
  statusText: '',
  startTime: null,
  endTime: null,
  threatProgress: null,
  errorMessage: null,
  workers: null,
}));

type ScanStatus = 'running' | 'pausing' | 'paused' | 'stopped' | 'complete' | 'failed';

/** Loose WebSocket event payload — the run stream contract is untyped. */
interface RunEvent {
  type?: string;
  stage?: string;
  percentage?: number;
  message?: string;
  sub_step?: string;
  server_ts?: number;
  details?: {
    phase?: string;
    threats?: ReviewThreat[];
    questions?: string[];
    message?: string;
    scanner_data?: ScannerData;
    workers?: StageWorker[];
    findings?: string[];
    index?: number;
    total?: number;
    threat_id?: string;
    app_id?: string;
    low_confidence?: boolean;
  };
}

interface ThreatReviewData {
  threats: ReviewThreat[];
  questions: string[];
  message: string;
}

function RunProgressBody({ runId }: { runId: string }) {
  const router = useRouter();
  const wsRef = useRef<RunWebSocketController | null>(null);

  const [stages, setStages] = useState<StageState[]>(INITIAL_STAGES);
  const [overallProgress, setOverallProgress] = useState(0);
  const [activityFeed, setActivityFeed] = useState<ActivityEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [pipelineComplete, setPipelineComplete] = useState(false);
  const [completedAppId, setCompletedAppId] = useState('');
  const [runAppId, setRunAppId] = useState('');
  const [runAppName, setRunAppName] = useState('');
  const [lowConfidence, setLowConfidence] = useState(false);
  // "running" | "paused" | "stopped" | "complete" | "failed"
  const [scanStatus, setScanStatus] = useState<ScanStatus>('running');
  // True while a pause/stop/resume HTTP request is in-flight
  const [controlPending, setControlPending] = useState(false);
  // Interviewer state
  const [showInterviewer, setShowInterviewer] = useState(false);
  const [chatHistory, setChatHistory] = useState<InterviewerChatEntry[]>([]);
  const [interviewerWaiting, setInterviewerWaiting] = useState(false);
  // Scanner review state
  const [showScannerReview, setShowScannerReview] = useState(false);
  const [scannerReviewData, setScannerReviewData] = useState<ScannerData | null>(null);
  const [confirmedReviewData, setConfirmedReviewData] = useState<ScannerData | null>(null);
  // Threat review state
  const [showThreatReview, setShowThreatReview] = useState(false);
  const [threatReviewData, setThreatReviewData] = useState<ThreatReviewData | null>(null);
  const [threatReviewWaiting, setThreatReviewWaiting] = useState(false);

  const handleInterviewerSubmit = useCallback(
    async (text: string) => {
      setChatHistory((prev) => [...prev, { role: 'user', text }]);
      setInterviewerWaiting(true);
      try {
        await submitRunResponse(runId, text);
      } catch (err) {
        setErrorMessage(`Failed to submit response: ${err instanceof Error ? err.message : String(err)}`);
        setInterviewerWaiting(false);
      }
    },
    [runId],
  );

  const handleInterviewerSkip = useCallback(async () => {
    setInterviewerWaiting(true);
    try {
      await submitRunResponse(runId, null as unknown as string);
      setShowInterviewer(false);
    } catch (err) {
      setErrorMessage(`Failed to skip interview: ${err instanceof Error ? err.message : String(err)}`);
    }
    setInterviewerWaiting(false);
  }, [runId]);

  const handleInterviewerBack = useCallback(async () => {
    setInterviewerWaiting(true);
    try {
      await submitRunResponse(runId, '__back__');
      // Backend will send a scanner_review awaiting_input event,
      // which the handler will route to the StageCard inline review.
      setShowInterviewer(false);
      setChatHistory([]);
    } catch (err) {
      setErrorMessage(`Failed to go back: ${err instanceof Error ? err.message : String(err)}`);
      setInterviewerWaiting(false);
    }
  }, [runId]);

  const handleScannerReviewConfirm = useCallback(async () => {
    try {
      await submitRunResponse(runId, JSON.stringify({ confirmed_only: true }));
      setConfirmedReviewData(scannerReviewData);
      setShowScannerReview(false);
      setScannerReviewData(null);
    } catch (err) {
      setErrorMessage(`Failed to confirm scanner review: ${err instanceof Error ? err.message : String(err)}`);
    }
  }, [runId, scannerReviewData]);

  const handleScannerReviewEdit = useCallback(
    async (edits: ScannerReviewEdits) => {
      try {
        await submitRunResponse(runId, JSON.stringify(edits));
        // Build confirmed data from the edits so the persisted view reflects changes
        const updated: ScannerData = { ...scannerReviewData, ...edits };
        // Recompute display tokens from edited values
        if (typeof updated.cloud_provider === 'string' && updated.cloud_provider.trim()) {
          updated._cloudTokens = updated.cloud_provider.split(/,\s*/).filter(Boolean);
        }
        if (typeof updated.tech_stack === 'string' && updated.tech_stack.trim()) {
          updated._techTokens = updated.tech_stack.split(/,\s*/).filter(Boolean);
        }
        setConfirmedReviewData(updated);
        setShowScannerReview(false);
        setScannerReviewData(null);
      } catch (err) {
        setErrorMessage(`Failed to submit scanner review edits: ${err instanceof Error ? err.message : String(err)}`);
      }
    },
    [runId, scannerReviewData],
  );

  const handleScannerReviewSkip = useCallback(async () => {
    try {
      await submitRunResponse(runId, null as unknown as string);
      setShowScannerReview(false);
      setScannerReviewData(null);
    } catch (err) {
      setErrorMessage(`Failed to skip scanner review: ${err instanceof Error ? err.message : String(err)}`);
    }
  }, [runId]);

  const handleThreatReviewApply = useCallback(
    async ({ edits, feedback }: ThreatReviewApply) => {
      setThreatReviewWaiting(true);
      try {
        await submitRunResponse(
          runId,
          JSON.stringify({ action: 'apply', edits: edits || {}, feedback: feedback || '' }),
        );
        // Backend will re-apply edits, optionally re-run the threat agent, then
        // emit a new awaiting_input event with the refreshed threats list.
      } catch (err) {
        setErrorMessage(`Failed to apply threat review: ${err instanceof Error ? err.message : String(err)}`);
        setThreatReviewWaiting(false);
      }
    },
    [runId],
  );

  const handleThreatReviewProceed = useCallback(async () => {
    setThreatReviewWaiting(true);
    try {
      await submitRunResponse(runId, JSON.stringify({ action: 'proceed' }));
      setShowThreatReview(false);
      setThreatReviewData(null);
    } catch (err) {
      setErrorMessage(`Failed to proceed past threat review: ${err instanceof Error ? err.message : String(err)}`);
      setThreatReviewWaiting(false);
    }
  }, [runId]);

  const appendActivity = useCallback((message: string, type: ActivityEntryType) => {
    setActivityFeed((prev) => [...prev, { time: formatTimestamp(), message, type }]);
  }, []);

  const handlePause = useCallback(async () => {
    setControlPending(true);
    try {
      await pauseRun(runId);
      setScanStatus('pausing');
      setControlPending(false);
      appendActivity('Pausing after current stage completes...', 'stage-complete');
    } catch (err) {
      setErrorMessage(`Failed to pause: ${err instanceof Error ? err.message : String(err)}`);
      setControlPending(false);
    }
  }, [runId, appendActivity]);

  const handleStop = useCallback(async () => {
    setControlPending(true);
    try {
      await stopRun(runId);
      if (scanStatus === 'paused') {
        // Executor has already exited; no WebSocket event is coming, so update
        // the UI directly from the HTTP response.
        setScanStatus('stopped');
        setControlPending(false);
        appendActivity('Scan stopped.', 'error');
      }
      // If running → stopped, wait for the "scan_stopped" WebSocket event.
    } catch (err) {
      setErrorMessage(`Failed to stop: ${err instanceof Error ? err.message : String(err)}`);
      setControlPending(false);
    }
  }, [runId, scanStatus, appendActivity]);

  const handleResume = useCallback(async () => {
    setControlPending(true);
    try {
      const { new_run_id } = await resumeRun(runId);
      // Navigate to the new run's progress page; the current WebSocket will
      // be cleaned up by the useEffect return/cleanup when the component unmounts.
      router.push(`/runs/${new_run_id}/progress`);
    } catch (err) {
      setErrorMessage(`Failed to resume: ${err instanceof Error ? err.message : String(err)}`);
      setControlPending(false);
    }
  }, [runId, router]);

  // Use a ref to access current stages without adding it to handleMessage deps.
  // This prevents the WebSocket reconnection loop caused by stages → handleMessage → useEffect cycle.
  const stagesRef = useRef(stages);
  stagesRef.current = stages;

  const handleMessage = useCallback(
    (event: MessageEvent) => {
      let data: RunEvent;
      try {
        data = JSON.parse(event.data) as RunEvent;
      } catch {
        return;
      }

      const { type, stage, percentage, message, sub_step, details } = data;
      const stageIdx = stage ? resolveStageIndex(stage) : -1;

      switch (type) {
        case 'stage_start': {
          if (stageIdx < 0) break;
          // Use server_ts when available for accurate timing (events may queue
          // before the WebSocket connects, making Date.now() inaccurate).
          const ts = data.server_ts || Date.now();
          setStages((prev) => {
            const next = prev.map((s, i) => {
              if (i < stageIdx) {
                // Auto-complete earlier stages; set endTime if not already set
                return {
                  ...s,
                  status: 'completed' as StageStatus,
                  progress: 100,
                  endTime: s.endTime || ts,
                };
              }
              if (i === stageIdx)
                return {
                  ...s,
                  status: 'in-progress' as StageStatus,
                  progress: 0,
                  statusText: message || '',
                  // Only set startTime if this stage hasn't started yet;
                  // avoids resetting when multiple internal stages (setup → context_analysis)
                  // map to the same UI stage.
                  startTime: s.startTime || ts,
                  endTime: null,
                };
              return s;
            });
            return next;
          });
          setOverallProgress(Math.round((stageIdx / STAGES.length) * 100));
          appendActivity(`Stage started: ${STAGES[stageIdx] || stage}`, 'stage-start');
          break;
        }

        case 'awaiting_input': {
          const awaitPhase = details?.phase || 'interviewer';

          if (awaitPhase === 'threat_review') {
            const trIdx = resolveStageIndex('Threat Review');
            setThreatReviewData({
              threats: details?.threats || [],
              questions: details?.questions || [],
              message: details?.message || message || '',
            });
            setShowThreatReview(true);
            setThreatReviewWaiting(false);
            if (trIdx >= 0) {
              setStages((prev) =>
                prev.map((s, i) =>
                  i === trIdx
                    ? { ...s, status: 'awaiting-input' as StageStatus, statusText: 'Waiting for your review' }
                    : s,
                ),
              );
            }
            appendActivity('Threat review is waiting for your input.', 'stage-start');
            break;
          }

          if (awaitPhase === 'scanner_review') {
            // Scanner review — show inline in the Repository Analysis StageCard
            const raIdx = resolveStageIndex('Repository Analysis');
            const rawData: ScannerData = details?.scanner_data || {};
            // Pre-compute token arrays for display
            const enriched: ScannerData = {
              ...rawData,
              _cloudTokens:
                typeof rawData.cloud_provider === 'string' && rawData.cloud_provider.trim()
                  ? rawData.cloud_provider.split(/,\s*/).filter(Boolean)
                  : Array.isArray(rawData.cloud_provider)
                    ? rawData.cloud_provider
                    : [],
              _techTokens:
                typeof rawData.tech_stack === 'string' && rawData.tech_stack.trim()
                  ? rawData.tech_stack.split(/,\s*/).filter(Boolean)
                  : Array.isArray(rawData.tech_stack)
                    ? rawData.tech_stack
                    : [],
            };
            setScannerReviewData(enriched);
            setShowScannerReview(true);
            if (raIdx >= 0) {
              setStages((prev) =>
                prev.map((s, i) =>
                  i === raIdx
                    ? { ...s, status: 'awaiting-input' as StageStatus, statusText: 'Waiting for your review' }
                    : s,
                ),
              );
            }
            appendActivity('Scanner review is waiting for your confirmation.', 'stage-start');
          } else {
            // Interviewer — show InterviewerPanel
            const cvIdx = resolveStageIndex('Context Validation');
            if (cvIdx >= 0) {
              setStages((prev) =>
                prev.map((s, i) =>
                  i === cvIdx
                    ? { ...s, status: 'awaiting-input' as StageStatus, statusText: 'Waiting for your input' }
                    : s,
                ),
              );
            }
            setChatHistory((prev) => [
              ...prev,
              {
                role: 'agent',
                message: details?.message || message || '',
                questions: details?.questions || [],
              },
            ]);
            setShowInterviewer(true);
            setInterviewerWaiting(false);
            appendActivity('Interviewer is waiting for your input.', 'stage-start');
          }
          break;
        }

        case 'stage_update':
        case 'stage_progress': {
          if (stageIdx < 0) break;
          const pct = typeof percentage === 'number' ? percentage : 0;
          setStages((prev) =>
            prev.map((s, i) =>
              i === stageIdx
                ? {
                    ...s,
                    status: 'in-progress' as StageStatus,
                    progress: pct,
                    statusText: sub_step || message || s.statusText,
                    workers: details?.workers || s.workers,
                  }
                : s,
            ),
          );
          setOverallProgress(Math.round(((stageIdx + pct / 100) / STAGES.length) * 100));
          break;
        }

        case 'scan_paused': {
          setScanStatus('paused');
          setControlPending(false);
          appendActivity('Scan paused. Click Resume to continue from where it left off.', 'stage-complete');
          break;
        }

        case 'scan_stopped': {
          setScanStatus('stopped');
          setControlPending(false);
          appendActivity('Scan stopped.', 'error');
          break;
        }

        case 'stage_complete': {
          if (stage === 'complete') {
            const completeTs = data.server_ts || Date.now();
            setStages((prev) =>
              prev.map((s) => ({
                ...s,
                status: 'completed' as StageStatus,
                progress: 100,
                endTime: s.endTime || completeTs,
              })),
            );
            setOverallProgress(100);
            setPipelineComplete(true);
            setScanStatus('complete');
            if (data.details?.app_id) setCompletedAppId(data.details.app_id);
            if (data.details?.low_confidence) setLowConfidence(true);
            setShowInterviewer(false);
            setShowThreatReview(false);
            appendActivity('Pipeline completed successfully!', 'stage-complete');
            break;
          }
          // Close panels when their stage completes
          if (stage === 'Context Validation') {
            setShowInterviewer(false);
            setInterviewerWaiting(false);
          }
          if (stage === 'Repository Analysis') {
            setShowScannerReview(false);
          }
          if (stage === 'Threat Review') {
            setShowThreatReview(false);
            setThreatReviewWaiting(false);
          }

          if (stageIdx < 0) break;
          const endTs = data.server_ts || Date.now();
          // Compute elapsed INSIDE the updater so we access the latest
          // pending startTime (stagesRef may be stale due to React batching).
          let durationStr = '0m 0s';
          setStages((prev) =>
            prev.map((s, i) => {
              if (i === stageIdx) {
                const elapsedMs = s.startTime ? endTs - s.startTime : 0;
                const totalSec = Math.floor(elapsedMs / 1000);
                const mins = Math.floor(totalSec / 60);
                const secs = totalSec % 60;
                durationStr = `${mins}m ${secs}s`;
                return {
                  ...s,
                  status: 'completed' as StageStatus,
                  progress: 100,
                  statusText: '',
                  endTime: endTs,
                  findings: details?.findings || null,
                };
              }
              return s;
            }),
          );
          setOverallProgress(Math.round(((stageIdx + 1) / STAGES.length) * 100));
          appendActivity(`Stage completed: ${STAGES[stageIdx] || stage} (${durationStr})`, 'stage-complete');
          break;
        }

        case 'threat_start': {
          if (stageIdx < 0) break;
          const current = details?.index ?? 0;
          const total = details?.total ?? 0;
          const pctStart = typeof percentage === 'number' ? percentage : 0;
          setStages((prev) =>
            prev.map((s, i) =>
              i === stageIdx
                ? {
                    ...s,
                    progress: pctStart,
                    threatProgress: {
                      current,
                      total,
                      completed: s.threatProgress?.completed ?? 0,
                    },
                    // Don't set statusText — threatProgress row in StageCard already shows this
                    statusText: '',
                  }
                : s,
            ),
          );
          setOverallProgress(Math.round(((stageIdx + pctStart / 100) / STAGES.length) * 100));
          break;
        }

        case 'threat_complete': {
          if (stageIdx < 0) break;
          const pctDone = typeof percentage === 'number' ? percentage : 0;
          setStages((prev) =>
            prev.map((s, i) =>
              i === stageIdx && s.threatProgress
                ? {
                    ...s,
                    progress: pctDone,
                    threatProgress: {
                      ...s.threatProgress,
                      completed: (s.threatProgress.completed ?? 0) + 1,
                    },
                  }
                : s,
            ),
          );
          setOverallProgress(Math.round(((stageIdx + pctDone / 100) / STAGES.length) * 100));
          const threatId = details?.threat_id || 'unknown';
          appendActivity(`Threat processed: ${threatId}`, 'threat-complete');
          break;
        }

        case 'error': {
          const errMsg = message || 'An unknown error occurred.';
          setErrorMessage(errMsg);
          setScanStatus('failed');
          if (stageIdx >= 0) {
            setStages((prev) =>
              prev.map((s, i) =>
                i === stageIdx
                  ? { ...s, status: 'failed' as StageStatus, statusText: errMsg, errorMessage: errMsg }
                  : s,
              ),
            );
          }
          appendActivity(`Error: ${errMsg}`, 'error');
          break;
        }

        case 'heartbeat':
        case 'log': {
          // Silently ignored — not added to activity feed
          break;
        }

        default:
          break;
      }
    },
    [appendActivity],
  );

  // WebSocket lifecycle — depends only on runId (stable).
  // handleMessage and appendActivity are stable useCallback refs.
  useEffect(() => {
    if (!runId) return;

    const ws = connectRunWebSocket(runId, {
      onOpen: () => {
        setConnected(true);
        appendActivity('Connected to run progress stream.', 'stage-start');
      },
      onMessage: handleMessage,
      onError: () => {
        setConnected(false);
        appendActivity('WebSocket error occurred.', 'error');
      },
      onClose: (e) => {
        setConnected(false);
        // Don't log reconnection-related close events as user-facing disconnects
        if (!e || e.code === 1000 || e.code === 4004) {
          appendActivity('Disconnected from run progress stream.', 'stage-complete');
        }
      },
    });

    wsRef.current = ws; // ws is now a { close() } controller

    return () => {
      if (wsRef.current) {
        wsRef.current.close(); // cancels reconnect timers + closes socket
        wsRef.current = null;
      }
    };
  }, [runId, handleMessage, appendActivity]);

  // Fetch the run's owning application so breadcrumbs can reflect context.
  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    getRun(runId)
      .then((data) => {
        if (cancelled) return;
        const id = data?.config?.app_id || '';
        if (id) {
          setRunAppId(id);
          return getApplication(id).then((app) => {
            if (!cancelled) setRunAppName(app?.name || '');
          });
        }
        return undefined;
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [runId]);

  const progressBreadcrumbs: BreadcrumbGroupProps.Item[] = runAppId
    ? [
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: runAppName || 'Application', href: `/applications/${runAppId}` },
        { text: 'Progress', href: `/runs/${runId}/progress` },
      ]
    : [
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: 'Progress', href: `/runs/${runId}/progress` },
      ];

  return (
    <AppShell activePage="/applications" breadcrumbs={progressBreadcrumbs}>
      <SpaceBetween size="l">
        <Header
          variant="h1"
          description={`Run ID: ${runId}`}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              {scanStatus === 'running' && (
                <Button onClick={handlePause} loading={controlPending} disabled={controlPending}>
                  Pause
                </Button>
              )}
              {(scanStatus === 'paused' || scanStatus === 'pausing') && (
                <Button variant="primary" onClick={handleResume} loading={controlPending} disabled={controlPending}>
                  Resume
                </Button>
              )}
              {(scanStatus === 'running' || scanStatus === 'paused' || scanStatus === 'pausing') && (
                <Button onClick={handleStop} disabled={controlPending}>
                  Stop
                </Button>
              )}
              <StatusIndicator type={connected ? 'success' : 'stopped'}>
                {connected ? 'Connected' : 'Disconnected'}
              </StatusIndicator>
            </SpaceBetween>
          }
        >
          Run Progress
        </Header>

        {/* Low confidence warning */}
        {lowConfidence && pipelineComplete && (
          <Alert type="warning" dismissible onDismiss={() => setLowConfidence(false)}>
            This threat model was generated with <strong>limited context</strong>. The context validation
            interview was skipped or had insufficient responses. Results should be treated as preliminary and
            validated with the development team.
          </Alert>
        )}

        {/* Success banner */}
        {pipelineComplete && (
          <Alert type="success" dismissible>
            Pipeline completed successfully!{' '}
            {completedAppId ? (
              <Link
                href={`/applications/${completedAppId}/versions/latest`}
                onFollow={(e) => {
                  e.preventDefault();
                  router.push(`/applications/${completedAppId}/versions/latest`);
                }}
              >
                View Dashboard
              </Link>
            ) : (
              <Link
                href="/applications"
                onFollow={(e) => {
                  e.preventDefault();
                  router.push('/applications');
                }}
              >
                View Applications
              </Link>
            )}
          </Alert>
        )}

        {/* Pausing banner */}
        {scanStatus === 'pausing' && (
          <Alert type="info">
            Pausing after the current stage completes. You can click <strong>Resume</strong> now — it will wait
            for the pause to finish, then continue automatically.
          </Alert>
        )}

        {/* Paused banner */}
        {scanStatus === 'paused' && (
          <Alert type="info">
            Scan paused after completing the current stage. Click <strong>Resume</strong> to continue from where
            it left off, or <strong>Stop</strong> to cancel permanently.
          </Alert>
        )}

        {/* Stopped banner */}
        {scanStatus === 'stopped' && (
          <Alert type="warning" dismissible onDismiss={() => setScanStatus('failed')}>
            Scan stopped. Start a new run to analyze this project again.
          </Alert>
        )}

        {/* Error banner */}
        {errorMessage && (
          <Alert type="error" dismissible onDismiss={() => setErrorMessage('')}>
            {errorMessage}
          </Alert>
        )}

        {/* Overall progress */}
        <Container header={<Header variant="h2">Overall Progress</Header>}>
          <SpaceBetween size="s">
            <ProgressBar
              value={overallProgress}
              label="Pipeline progress"
              description={pipelineComplete ? 'All stages completed' : `${overallProgress}% complete`}
              status={errorMessage ? 'error' : pipelineComplete ? 'success' : 'in-progress'}
            />
            {scanStatus === 'running' && (
              <Box color="text-status-inactive" fontSize="body-s">
                You can safely leave this page and return at any time — your run will continue in the background.
              </Box>
            )}
          </SpaceBetween>
        </Container>

        {/* Pipeline stages — now using StageCard components */}
        <Container header={<Header variant="h2">Pipeline Stages</Header>}>
          <SpaceBetween size="xs">
            {stages.map((stage) => (
              <StageCard
                key={stage.name}
                name={stage.name}
                status={stage.status}
                progress={stage.progress}
                statusText={stage.statusText}
                startTime={stage.startTime}
                endTime={stage.endTime}
                threatProgress={stage.threatProgress}
                errorMessage={stage.errorMessage}
                findings={stage.findings}
                workers={stage.workers}
                scannerReview={
                  stage.name === 'Repository Analysis' && showScannerReview ? scannerReviewData : null
                }
                confirmedContext={stage.name === 'Repository Analysis' ? confirmedReviewData : null}
                onScannerReviewConfirm={handleScannerReviewConfirm}
                onScannerReviewEdit={handleScannerReviewEdit}
                onScannerReviewSkip={handleScannerReviewSkip}
              />
            ))}
          </SpaceBetween>
        </Container>

        {/* Interviewer Panel */}
        {showInterviewer && (
          <InterviewerPanel
            chatHistory={chatHistory}
            onSubmit={handleInterviewerSubmit}
            onSkip={handleInterviewerSkip}
            onBack={handleInterviewerBack}
            waiting={interviewerWaiting}
          />
        )}

        {/* Threat Review Panel */}
        {showThreatReview && threatReviewData && (
          <ThreatReviewPanel
            threats={threatReviewData.threats}
            questions={threatReviewData.questions}
            message={threatReviewData.message}
            onApply={handleThreatReviewApply}
            onProceed={handleThreatReviewProceed}
            waiting={threatReviewWaiting}
          />
        )}

        {/* Activity Feed */}
        <Container header={<Header variant="h2">Activity Feed</Header>}>
          <ActivityFeed entries={activityFeed} />
        </Container>
      </SpaceBetween>
    </AppShell>
  );
}

export default function RunProgressKeyedView() {
  const params = useRealParams<{ runId: string }>('/runs/[runId]/progress');
  const runId = params.runId;

  if (!runId) {
    return (
      <AppShell
        activePage="/applications"
        breadcrumbs={[
          { text: 'Home', href: '/' },
          { text: 'Applications', href: '/applications' },
          { text: 'Progress', href: '#' },
        ]}
      >
        <Alert type="error">No run ID provided. Please start a new run.</Alert>
      </AppShell>
    );
  }

  // `key={runId}` forces a fresh component instance per run id, matching the
  // legacy RunProgressPageKeyed remount behavior so run-scoped state doesn't
  // bleed across a Resume that navigates to a new id.
  return <RunProgressBody key={runId} runId={runId} />;
}
