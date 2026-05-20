import React, { useState } from 'react';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import Alert from '@cloudscape-design/components/alert';
import Modal from '@cloudscape-design/components/modal';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Toggle from '@cloudscape-design/components/toggle';
import {
  exportCustomPdf,
  exportCustomCsvBundle,
  downloadThreatforestReport,
} from '../utils/export-service';
import { buildExportFilename } from '../utils/export-filename';
import CustomiseExportModal from './CustomiseExportModal';

// Top-level menu shape — replaces the previous nested submenus. Matches
// the row-level VersionRowExportMenu so the user sees the same options
// in both places.
function buildExportItems({ fullAppExport }) {
  const reportItems = [{ id: 'report-version', text: 'This version only' }];
  if (fullAppExport) {
    reportItems.push({ id: 'report-full-app', text: 'Full application history' });
  }
  return [
    { id: 'customise', text: 'Customise export...' },
    {
      id: 'export-tfreport',
      text: 'Export ThreatForest Report',
      items: reportItems,
    },
  ];
}

export default function ExportButton({
  summaryData,
  appId,
  versionId,
  appName,
  versionLabel,
  fullAppExport = false,
}) {
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  // Customise-export modal state.
  const [customiseOpen, setCustomiseOpen] = useState(false);
  const [customiseError, setCustomiseError] = useState(null);

  // ThreatForest Report modal state — separate flow because it's a server-built
  // bundle with its own toggle (scanner context) rather than client-rendered.
  const [reportPrompt, setReportPrompt] = useState(null); // { mode } | null
  const [includeScannerContext, setIncludeScannerContext] = useState(true);

  function handleClick({ detail }) {
    setError(null);

    if (detail.id === 'customise') {
      const trees = summaryData?.attack_trees;
      if (!summaryData || !Array.isArray(trees) || trees.length === 0) {
        setError('No threat model data available to export.');
        return;
      }
      setCustomiseError(null);
      setCustomiseOpen(true);
      return;
    }

    if (detail.id === 'report-version' || detail.id === 'report-full-app') {
      if (!appId) {
        setError('Cannot export report: application id is unavailable.');
        return;
      }
      if (detail.id === 'report-version' && !versionId) {
        setError('Cannot export report: version id is unavailable.');
        return;
      }
      setIncludeScannerContext(true);
      setReportPrompt({ mode: detail.id });
    }
  }

  const fname = (scope, extension) =>
    buildExportFilename({
      appId,
      versionId,
      appName,
      versionLabel,
      scope,
      extension,
    });

  async function handleCustomiseConfirm({ sections, format }) {
    setBusy(true);
    setCustomiseError(null);
    try {
      if (format === 'pdf') {
        exportCustomPdf(summaryData, sections, fname(null, 'pdf'));
      } else {
        await exportCustomCsvBundle(summaryData, sections, fname(null, 'csv'));
      }
      setCustomiseOpen(false);
    } catch (err) {
      setCustomiseError(err.message || 'Failed to generate export.');
    } finally {
      setBusy(false);
    }
  }

  async function handleReportConfirm() {
    if (!reportPrompt) return;
    setBusy(true);
    setError(null);
    try {
      await downloadThreatforestReport({
        appId,
        versionId: reportPrompt.mode === 'report-version' ? versionId : undefined,
        includeScannerContext,
      });
      setReportPrompt(null);
    } catch (err) {
      setError(err.message || 'Failed to export ThreatForest report.');
    } finally {
      setBusy(false);
    }
  }

  const threatCount = Array.isArray(summaryData?.attack_trees)
    ? summaryData.attack_trees.length
    : 0;

  return (
    <>
      {error && (
        <Alert
          type="error"
          dismissible
          onDismiss={() => setError(null)}
          data-testid="export-error-alert"
        >
          {error}
        </Alert>
      )}
      <ButtonDropdown
        items={buildExportItems({ fullAppExport })}
        onItemClick={handleClick}
        expandableGroups
        data-testid="export-button"
      >
        Export
      </ButtonDropdown>

      <CustomiseExportModal
        visible={customiseOpen}
        onDismiss={() => !busy && setCustomiseOpen(false)}
        onConfirm={handleCustomiseConfirm}
        loading={busy}
        error={customiseError}
        threatCount={threatCount}
      />

      {/* ThreatForest Report scanner-context confirmation. Kept separate
          from the customise modal — it's a different artifact (server-built
          bundle for handoff) with its own toggle. */}
      <Modal
        visible={reportPrompt !== null}
        onDismiss={() => !busy && setReportPrompt(null)}
        header="Export ThreatForest Report"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button
                variant="link"
                onClick={() => setReportPrompt(null)}
                disabled={busy}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={handleReportConfirm}
                loading={busy}
                data-testid="confirm-tfreport-export"
              >
                Download
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box variant="p">
            Bundles this {reportPrompt?.mode === 'report-full-app' ? 'application' : 'threat model'}
            {' '}as a <code>.tfreport</code> file that another ThreatForest user
            can drop into their <code>.threatforest/imports/</code> folder.
            Imported applications are read-only — the recipient can browse,
            export, and edit mitigation status but cannot re-run.
          </Box>
          <Toggle
            checked={includeScannerContext}
            onChange={({ detail }) => setIncludeScannerContext(detail.checked)}
            data-testid="toggle-scanner-context"
          >
            Include scanner context (file paths and code excerpts)
          </Toggle>
          <Box variant="small" color="text-body-secondary">
            On by default for intra-team handoff. Turn off when sharing
            outside your team to redact source-code references.
          </Box>
        </SpaceBetween>
      </Modal>
    </>
  );
}
