import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import CloudscapeShell from '../components/CloudscapeShell';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Alert from '@cloudscape-design/components/alert';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import Link from '@cloudscape-design/components/link';
import Button from '@cloudscape-design/components/button';
import StageCard from '../components/StageCard';
import ActivityFeed from '../components/ActivityFeed';
import InterviewerPanel from '../components/InterviewerPanel';
import { connectRunWebSocket, pauseRun, stopRun, resumeRun, submitRunResponse } from '../api-client';

const STAGES = [
  'Repository Analysis',
  'Context Validation',
  'Threat Generation',
  'Parallel Analysis',
  'Dashboard Generation',
];

const stageIndexMap = {
  'Repository Analysis': 0,
  'Context Validation': 1,
  'Threat Generation': 2,
  'Parallel Analysis': 3,
  'Dashboard Generation': 4,
  // Fallback internal names
  setup: 0,
  context_analysis: 0,
  extraction: 0,
  tree_generation: 3,
  ttc_enrichment: 3,
  mitigation: 3,
  summary: 4,
};

function resolveStageIndex(stageName) {
  if (stageName in stageIndexMap) return stageIndexMap[stageName];
  // Try case-insensitive match against STAGES
  const lower = stageName.toLowerCase();
  const idx = STAGES.findIndex((s) => s.toLowerCase() === lower);
  return idx >= 0 ? idx : -1;
}

function formatTimestamp() {
  return new Date().toLocaleTimeString();
}

const INITIAL_STAGES = STAGES.map((name) => ({
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

export default function RunProgressPage() {
  const { runId } = useParams();
  const navigate = useNavigate();
  const wsRef = useRef(null);

  const [stages, setStages] = useState(INITIAL_STAGES);
  const [overallProgress, setOverallProgress] = useState(0);
  const [activityFeed, setActivityFeed] = useState([]);
  const [connected, setConnected] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [pipelineComplete, setPipelineComplete] = useState(false);
  const [completedAppId, setCompletedAppId] = useState('');
  const [lowConfidence, setLowConfidence] = useState(false);
  // "running" | "paused" | "stopped" | "complete" | "failed"
  const [scanStatus, setScanStatus] = useState('running');
  // True while a pause/stop/resume HTTP request is in-flight
  const [controlPending, setControlPending] = useState(false);
  // Interviewer state
  const [showInterviewer, setShowInterviewer] = useState(false);
  const [chatHistory, setChatHistory] = useState([]);
  const [interviewerWaiting, setInterviewerWaiting] = useState(false);
  // Scanner review state
  const [showScannerReview, setShowScannerReview] = useState(false);
  const [scannerReviewData, setScannerReviewData] = useState(null);

  const handleInterviewerSubmit = useCallback(async (text) => {
    setChatHistory((prev) => [...prev, { role: 'user', text }]);
    setInterviewerWaiting(true);
    try {
      await submitRunResponse(runId, text);
    } catch (err) {
      setErrorMessage(`Failed to submit response: ${err.message}`);
      setInterviewerWaiting(false);
    }
  }, [runId]);

  const handleInterviewerSkip = useCallback(async () => {
    setInterviewerWaiting(true);
    try {
      await submitRunResponse(runId, null);
      setShowInterviewer(false);
    } catch (err) {
      setErrorMessage(`Failed to skip interview: ${err.message}`);
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
      setErrorMessage(`Failed to go back: ${err.message}`);
      setInterviewerWaiting(false);
    }
  }, [runId]);

  const handleScannerReviewConfirm = useCallback(async () => {
    try {
      await submitRunResponse(runId, JSON.stringify({ confirmed_only: true }));
      setShowScannerReview(false);
      setScannerReviewData(null);
    } catch (err) {
      setErrorMessage(`Failed to confirm scanner review: ${err.message}`);
    }
  }, [runId]);

  const handleScannerReviewEdit = useCallback(async (edits) => {
    try {
      await submitRunResponse(runId, JSON.stringify(edits));
      setShowScannerReview(false);
      setScannerReviewData(null);
    } catch (err) {
      setErrorMessage(`Failed to submit scanner review edits: ${err.message}`);
    }
  }, [runId]);

  const handleScannerReviewSkip = useCallback(async () => {
    try {
      await submitRunResponse(runId, null);
      setShowScannerReview(false);
      setScannerReviewData(null);
    } catch (err) {
      setErrorMessage(`Failed to skip scanner review: ${err.message}`);
    }
  }, [runId]);

  const appendActivity = useCallback((message, type) => {
    setActivityFeed((prev) => [...prev, { time: formatTimestamp(), message, type }]);
  }, []);

  const handlePause = useCallback(async () => {
    setControlPending(true);
    try {
      await pauseRun(runId);
      // scanStatus will update when the "scan_paused" WebSocket event arrives.
    } catch (err) {
      setErrorMessage(`Failed to pause: ${err.message}`);
      setControlPending(false);
    }
  }, [runId]);

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
      setErrorMessage(`Failed to stop: ${err.message}`);
      setControlPending(false);
    }
  }, [runId, scanStatus, appendActivity]);

  const handleResume = useCallback(async () => {
    setControlPending(true);
    try {
      const { new_run_id } = await resumeRun(runId);
      // Navigate to the new run's progress page; the current WebSocket will
      // be cleaned up by the useEffect return/cleanup when the component unmounts.
      navigate(`/runs/${new_run_id}/progress`);
    } catch (err) {
      setErrorMessage(`Failed to resume: ${err.message}`);
      setControlPending(false);
    }
  }, [runId, navigate]);

  // Use a ref to access current stages without adding it to handleMessage deps.
  // This prevents the WebSocket reconnection loop caused by stages → handleMessage → useEffect cycle.
  const stagesRef = useRef(stages);
  stagesRef.current = stages;

  const handleMessage = useCallback(
    (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
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
                  status: 'completed',
                  progress: 100,
                  endTime: s.endTime || ts,
                };
              }
              if (i === stageIdx)
                return {
                  ...s,
                  status: 'in-progress',
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

          if (awaitPhase === 'scanner_review') {
            // Scanner review — show inline in the Repository Analysis StageCard
            const raIdx = resolveStageIndex('Repository Analysis');
            const rawData = details?.scanner_data || {};
            // Pre-compute token arrays for display
            const enriched = {
              ...rawData,
              _cloudTokens: typeof rawData.cloud_provider === 'string' && rawData.cloud_provider.trim()
                ? rawData.cloud_provider.split(/,\s*/).filter(Boolean)
                : (Array.isArray(rawData.cloud_provider) ? rawData.cloud_provider : []),
              _techTokens: typeof rawData.tech_stack === 'string' && rawData.tech_stack.trim()
                ? rawData.tech_stack.split(/,\s*/).filter(Boolean)
                : (Array.isArray(rawData.tech_stack) ? rawData.tech_stack : []),
            };
            setScannerReviewData(enriched);
            setShowScannerReview(true);
            if (raIdx >= 0) {
              setStages((prev) =>
                prev.map((s, i) =>
                  i === raIdx
                    ? { ...s, status: 'awaiting-input', statusText: 'Waiting for your review' }
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
                    ? { ...s, status: 'awaiting-input', statusText: 'Waiting for your input' }
                    : s,
                ),
              );
            }
            setChatHistory((prev) => [...prev, {
              role: 'agent',
              message: details?.message || message || '',
              questions: details?.questions || [],
            }]);
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
                ? { ...s, status: 'in-progress', progress: pct, statusText: sub_step || message || s.statusText, workers: details?.workers || s.workers }
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
                status: 'completed',
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
                  status: 'completed',
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
          appendActivity(
            `Stage completed: ${STAGES[stageIdx] || stage} (${durationStr})`,
            'stage-complete',
          );
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
                      completed: s.threatProgress.completed + 1,
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
                  ? { ...s, status: 'failed', statusText: errMsg, errorMessage: errMsg }
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

  if (!runId) {
    return (
      <CloudscapeShell
        activePage="/new-run"
        breadcrumbs={[
          { text: 'Home', href: '/' },
          { text: 'New Run', href: '/new-run' },
          { text: 'Progress', href: '#' },
        ]}
      >
        <Alert type="error">No run ID provided. Please start a new run.</Alert>
      </CloudscapeShell>
    );
  }

  return (
    <CloudscapeShell
      activePage="/new-run"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'New Run', href: '/new-run' },
        { text: 'Progress', href: `/runs/${runId}/progress` },
      ]}
    >
      <SpaceBetween size="l">
        <Header
          variant="h1"
          description={`Run ID: ${runId}`}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              {scanStatus === 'running' && (
                <Button
                  onClick={handlePause}
                  loading={controlPending}
                  disabled={controlPending}
                >
                  Pause
                </Button>
              )}
              {scanStatus === 'paused' && (
                <Button
                  variant="primary"
                  onClick={handleResume}
                  loading={controlPending}
                  disabled={controlPending}
                >
                  Resume
                </Button>
              )}
              {(scanStatus === 'running' || scanStatus === 'paused') && (
                <Button
                  onClick={handleStop}
                  disabled={controlPending}
                >
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
            This threat model was generated with <strong>limited context</strong>. The
            context validation interview was skipped or had insufficient responses.
            Results should be treated as preliminary and validated with the development team.
          </Alert>
        )}

        {/* Success banner */}
        {pipelineComplete && (
          <Alert type="success" dismissible>
            Pipeline completed successfully!{' '}
            {completedAppId ? (
              <Link href={`/applications/${completedAppId}/versions/latest`}>
                View Dashboard
              </Link>
            ) : (
              <Link href="/applications">View Applications</Link>
            )}
          </Alert>
        )}

        {/* Paused banner */}
        {scanStatus === 'paused' && (
          <Alert type="info">
            Scan paused after completing the current stage. Click <strong>Resume</strong> to
            continue from where it left off, or <strong>Stop</strong> to cancel permanently.
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
          <ProgressBar
            value={overallProgress}
            label="Pipeline progress"
            description={
              pipelineComplete
                ? 'All stages completed'
                : `${overallProgress}% complete`
            }
            status={
              errorMessage ? 'error' : pipelineComplete ? 'success' : 'in-progress'
            }
          />
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
                scannerReview={stage.name === 'Repository Analysis' && showScannerReview ? scannerReviewData : null}
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

        {/* Activity Feed */}
        <Container header={<Header variant="h2">Activity Feed</Header>}>
          <ActivityFeed entries={activityFeed} />
        </Container>
      </SpaceBetween>
    </CloudscapeShell>
  );
}
