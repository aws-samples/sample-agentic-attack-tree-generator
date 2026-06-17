'use client';

import { useEffect, useRef, useState, type ChangeEvent } from 'react';
import Button from '@cloudscape-design/components/button';
import Modal from '@cloudscape-design/components/modal';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Alert from '@cloudscape-design/components/alert';
import Spinner from '@cloudscape-design/components/spinner';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import {
  getImportsInfo,
  uploadTfReport,
  type ImportsInfoResponse,
} from '@/api/client';

/**
 * The per-import result envelope the modal renders. The contract returns
 * `{ result: { status, folder_name, versions_added, ... } }`; the legacy UI
 * treats `versions_added` as an array (it reads `.length`), so we model it
 * loosely here to preserve that behaviour.
 */
interface ImportResult {
  status: 'imported' | 'merged' | 'skipped' | 'failed' | string;
  folder_name?: string;
  versions_added?: unknown[];
  error?: string;
  [key: string]: unknown;
}

export interface ImportReportButtonProps {
  onImported?: (result: ImportResult) => void;
}

/**
 * "Import a report" button + modal for the Applications page header.
 *
 * Two affordances in one place:
 *   1. A native file picker — the user chooses a ``.tfreport`` and the
 *      backend imports it inline; the modal shows the outcome
 *      (imported/merged/failed) before closing.
 *   2. The absolute path of the drop-folder, copy-able for users who
 *      prefer to drag-and-drop into Finder/Explorer rather than upload
 *      through the browser.
 *
 * On success we call ``onImported`` so the parent can refresh its list
 * without us having to refetch from inside the modal.
 */
export default function ImportReportButton({ onImported }: ImportReportButtonProps) {
  const [open, setOpen] = useState(false);
  const [info, setInfo] = useState<ImportsInfoResponse | null>(null);
  const [infoLoading, setInfoLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setInfoLoading(true);
    getImportsInfo()
      .then((data) => { if (!cancelled) setInfo(data); })
      .catch(() => { /* non-blocking — the upload still works without it */ })
      .finally(() => { if (!cancelled) setInfoLoading(false); });
    return () => { cancelled = true; };
  }, [open]);

  const reset = () => {
    setResult(null);
    setError('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const close = () => {
    if (uploading) return;
    setOpen(false);
    // Defer reset so the modal close animation doesn't strip the
    // success/failure message before it fades out.
    setTimeout(reset, 200);
  };

  const handleFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setError('');
    setResult(null);
    if (!file.name.endsWith('.tfreport')) {
      setError('Please choose a file that ends in .tfreport.');
      // Clear the input so picking the same file again triggers a change.
      if (fileInputRef.current) fileInputRef.current.value = '';
      return;
    }
    setUploading(true);
    try {
      const response = await uploadTfReport(file);
      // The API client models `versions_added` as a number, but this modal
      // (mirroring the legacy UI) treats it loosely as an array (reads
      // `.length`). The shapes intentionally diverge, so cast through unknown.
      const r = (response?.result as unknown as ImportResult | undefined) || null;
      setResult(r);
      if (r && (r.status === 'imported' || r.status === 'merged')) {
        onImported?.(r);
      }
    } catch (err) {
      setError((err as Error).message || 'Upload failed.');
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const copyPath = async () => {
    if (!info?.imports_dir) return;
    try {
      await navigator.clipboard.writeText(info.imports_dir);
    } catch {
      // Clipboard write requires user gesture + permissions; fail silently.
    }
  };

  return (
    <>
      <Button
        iconName="upload"
        onClick={() => setOpen(true)}
        data-testid="import-report-button"
      >
        Import a report
      </Button>

      <Modal
        visible={open}
        onDismiss={close}
        header="Import a ThreatForest report"
        size="medium"
        footer={
          <Box float="right">
            <Button variant="link" onClick={close} disabled={uploading}>
              {result || error ? 'Close' : 'Cancel'}
            </Button>
          </Box>
        }
      >
        <SpaceBetween size="m">
          {/* Each direct child carries a stable key: SpaceBetween renders its
              children as a list, and the conditional blocks below would
              otherwise trigger React's missing-key warning. */}
          <Box key="intro" variant="p">
            Choose a <code>.tfreport</code> bundle exported from another
            ThreatForest install. The application will appear in your list
            with an <strong>Imported</strong> badge.
          </Box>

          <Box key="file-input">
            <input
              ref={fileInputRef}
              type="file"
              accept=".tfreport"
              onChange={handleFileChange}
              disabled={uploading}
              data-testid="import-report-file-input"
            />
          </Box>

          {uploading && (
            <Box key="uploading">
              <Spinner /> Importing…
            </Box>
          )}

          {/* Use a ternary, not `error && (...)`: `error` is a string, so
              `'' && <Alert/>` evaluates to the empty string `''` — a stray text
              child that React keeps in SpaceBetween's child list and flags with
              the "unique key" warning. `? : null` renders nothing when empty. */}
          {error ? (
            <Alert key="error" type="error" header="Import failed">
              {error}
            </Alert>
          ) : null}

          {result && result.status === 'imported' && (
            <Alert key="result-imported" type="success" header="Imported">
              Application imported as <strong>{result.folder_name}</strong>
              {result.versions_added?.length
                ? ` with ${result.versions_added.length} threat model${result.versions_added.length === 1 ? '' : 's'}.`
                : '.'}
            </Alert>
          )}
          {result && result.status === 'merged' && (
            <Alert key="result-merged" type="success" header="Merged into existing app">
              Added {result.versions_added?.length ?? 0} new version
              {result.versions_added?.length === 1 ? '' : 's'} to{' '}
              <strong>{result.folder_name}</strong>.
            </Alert>
          )}
          {result && result.status === 'skipped' && (
            <Alert key="result-skipped" type="info" header="Nothing new to import">
              All versions in this bundle are already present.
            </Alert>
          )}
          {result && result.status === 'failed' && (
            <Alert key="result-failed" type="error" header="Could not import">
              {result.error || 'Unknown error.'}
            </Alert>
          )}

          <details key="drop-folder">
            <summary>
              <span style={{ fontSize: '0.9em' }}>
                Or drop the file directly in the imports folder
              </span>
            </summary>
            <Box padding={{ top: 's' }}>
              <SpaceBetween size="xs">
                <Box key="drop-blurb" variant="small" color="text-body-secondary">
                  Bundles dropped here are picked up the next time you load
                  the Applications page.
                </Box>
                {infoLoading ? (
                  <Spinner key="info-loading" />
                ) : info ? (
                  <SpaceBetween key="info-dir" direction="horizontal" size="xs">
                    <Box variant="code">{info.imports_dir}</Box>
                    <Button
                      iconName="copy"
                      onClick={copyPath}
                      ariaLabel="Copy path"
                    />
                  </SpaceBetween>
                ) : (
                  <Box key="info-missing" variant="small" color="text-status-inactive">
                    Imports directory unavailable.
                  </Box>
                )}
                {info?.failed?.length ? (
                  <Box key="info-failed">
                    <StatusIndicator type="warning">
                      {info.failed.length} bundle
                      {info.failed.length === 1 ? '' : 's'} failed previously —
                      check <code>imports/failed/</code>.
                    </StatusIndicator>
                  </Box>
                ) : null}
              </SpaceBetween>
            </Box>
          </details>
        </SpaceBetween>
      </Modal>
    </>
  );
}
