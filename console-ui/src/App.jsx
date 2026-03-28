import React from 'react';
import { BrowserRouter, Routes, Route, useParams } from 'react-router-dom';
import HomePage from './pages/HomePage';
import ApplicationsPage from './pages/ApplicationsPage';
import AppDetailPage from './pages/AppDetailPage';
import ThreatModelSummaryPage from './pages/ThreatModelSummaryPage';
import VersionDetailPage from './pages/VersionDetailPage';
import NewRunPage from './pages/NewRunPage';
import RunProgressPage from './pages/RunProgressPage';
import ConfigurePage from './pages/ConfigurePage';
import PausedRunsPage from './pages/PausedRunsPage';

// Wrapper that forces RunProgressPage to fully remount when the runId changes.
// Without this, React Router reuses the same component instance when navigating
// from one run to another (e.g. after Resume), so state like controlPending and
// scanStatus bleeds over from the old run.
function RunProgressPageKeyed() {
  const { runId } = useParams();
  return <RunProgressPage key={runId} />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/applications" element={<ApplicationsPage />} />
        <Route path="/applications/:appId" element={<AppDetailPage />} />
        <Route path="/applications/:appId/versions/:versionId" element={<ThreatModelSummaryPage />} />
        <Route path="/applications/:appId/versions/:versionId/threats/:threatIndex" element={<VersionDetailPage />} />
        <Route path="/new-run" element={<NewRunPage />} />
        <Route path="/paused-runs" element={<PausedRunsPage />} />
        <Route path="/runs/:runId/progress" element={<RunProgressPageKeyed />} />
        <Route path="/configure" element={<ConfigurePage />} />
      </Routes>
    </BrowserRouter>
  );
}
