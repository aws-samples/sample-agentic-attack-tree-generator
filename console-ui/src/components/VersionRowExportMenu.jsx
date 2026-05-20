import React, { useRef, useState } from 'react';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import {
  exportCustomPdf,
  exportCustomCsvBundle,
  downloadThreatforestReport,
} from '../utils/export-service';
import { buildExportFilename } from '../utils/export-filename';
import CustomiseExportModal from './CustomiseExportModal';

// Flat list — same shape as the page-level ExportButton dropdown but with
// no nested groups (the row context can't fit a submenu reliably).
const EXPORT_ITEMS = [
  { id: 'customise', text: 'Customise export...' },
  { id: 'tfreport', text: 'ThreatForest Report (.tfreport)' },
];

/**
 * Per-row export menu rendered next to Delete on the AppOverviewPage
 * version table. Identical user choices as the page-level ``ExportButton``
 * but the version's full ``/data`` blob is fetched lazily on first
 * interaction — most users won't export every old version, so we don't
 * pre-fetch.
 *
 * Disabled for versions that don't have a completed dashboard: live runs
 * have no merged data yet, abandoned ones never will.
 *
 * Errors are surfaced via the parent's ``onError`` callback so this menu
 * stays purely a row-level affordance.
 */
export default function VersionRowExportMenu({
  appId,
  appName,
  version,
  disabled = false,
  onError,
}) {
  const [busy, setBusy] = useState(false);
  const [customiseOpen, setCustomiseOpen] = useState(false);
  const [customiseError, setCustomiseError] = useState(null);
  const [data, setData] = useState(null); // Cached /data response.

  // Cache the merged /data response per version so re-opens don't refetch.
  const cacheRef = useRef(null);

  async function loadData() {
    if (cacheRef.current) return cacheRef.current;
    const url = `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(version.id)}/data`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to load version data (HTTP ${response.status})`);
    }
    const json = await response.json();
    cacheRef.current = json;
    return json;
  }

  async function handleClick({ detail }) {
    if (disabled || busy) return;

    if (detail.id === 'tfreport') {
      setBusy(true);
      try {
        await downloadThreatforestReport({
          appId,
          versionId: version.id,
          includeScannerContext: true,
        });
      } catch (err) {
        if (onError) onError(err.message || 'Export failed.');
      } finally {
        setBusy(false);
      }
      return;
    }

    if (detail.id === 'customise') {
      // Open the modal immediately and fetch in parallel so the user can
      // tick checkboxes while the data loads. The Download button stays
      // disabled (via ``loading`` prop) until both the user has confirmed
      // and the data is ready.
      setCustomiseError(null);
      setCustomiseOpen(true);
      setBusy(true);
      try {
        const json = await loadData();
        setData(json);
      } catch (err) {
        setCustomiseError(err.message || 'Failed to load version data.');
      } finally {
        setBusy(false);
      }
    }
  }

  async function handleCustomiseConfirm({ sections, format }) {
    if (!data) {
      setCustomiseError('Version data not loaded yet — please wait.');
      return;
    }
    setBusy(true);
    setCustomiseError(null);
    try {
      const fname = (extension) =>
        buildExportFilename({
          appId,
          versionId: version.id,
          appName,
          versionLabel: version.display_name || version.id,
          scope: null,
          extension,
        });
      if (format === 'pdf') {
        exportCustomPdf(data, sections, fname('pdf'));
      } else {
        await exportCustomCsvBundle(data, sections, fname('csv'));
      }
      setCustomiseOpen(false);
    } catch (err) {
      setCustomiseError(err.message || 'Failed to generate export.');
    } finally {
      setBusy(false);
    }
  }

  const threatCount = Array.isArray(data?.attack_trees)
    ? data.attack_trees.length
    : 0;

  return (
    <>
      <ButtonDropdown
        items={EXPORT_ITEMS}
        onItemClick={handleClick}
        variant="inline-link"
        disabled={disabled}
        loading={busy && !customiseOpen}
        // Portal the menu out of the cell so the table's row-level overflow
        // clipping (used for column-resize handles) doesn't cut it off.
        expandToViewport
        data-testid={`export-version-${version.id}`}
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
    </>
  );
}
