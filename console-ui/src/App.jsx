import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import HomePage from './pages/HomePage';
import ApplicationsPage from './pages/ApplicationsPage';
import AppDetailPage from './pages/AppDetailPage';
import VersionDetailPage from './pages/VersionDetailPage';
import NewRunPage from './pages/NewRunPage';
import RunProgressPage from './pages/RunProgressPage';
import ConfigurePage from './pages/ConfigurePage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/applications" element={<ApplicationsPage />} />
        <Route path="/applications/:appId" element={<AppDetailPage />} />
        <Route path="/applications/:appId/versions/:versionId" element={<VersionDetailPage />} />
        <Route path="/new-run" element={<NewRunPage />} />
        <Route path="/runs/:runId/progress" element={<RunProgressPage />} />
        <Route path="/configure" element={<ConfigurePage />} />
      </Routes>
    </BrowserRouter>
  );
}
