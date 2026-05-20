import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Header from '@cloudscape-design/components/header';
import Button from '@cloudscape-design/components/button';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Alert from '@cloudscape-design/components/alert';
import Spinner from '@cloudscape-design/components/spinner';
import Container from '@cloudscape-design/components/container';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Link from '@cloudscape-design/components/link';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Table from '@cloudscape-design/components/table';
import Modal from '@cloudscape-design/components/modal';
import Input from '@cloudscape-design/components/input';
import FormField from '@cloudscape-design/components/form-field';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import Toggle from '@cloudscape-design/components/toggle';
import CloudscapeShell from '../components/CloudscapeShell';
import BusinessContextPanel from '../components/BusinessContextPanel';
import DirectoryPicker from '../components/DirectoryPicker';
import VersionRowExportMenu from '../components/VersionRowExportMenu';
import { downloadThreatforestReport } from '../utils/export-service';
import {
  getApplication,
  getApplications,
  getApplicationVersions,
  updateApplication,
  deleteApplicationRecord,
  deleteApplicationVersion,
} from '../api-client';

/**
 * AppOverviewPage — the v2 landing page for an application.
 *
 * Replaces the legacy AppDetailPage. Loads the persistent Application record
 * (including its BusinessContext) alongside folder-derived version history
 * and presents them as a single overview:
 *
 *   • Header: app name + rename pencil
 *   • Primary CTAs: "Start new threat model", "Create a new version"
 *   • BusinessContextPanel (view + edit modal)
 *   • Latest threat model card
 *   • Version history table
 *   • Danger zone: delete
 */
function renderStatus(status) {
  switch (status) {
    case 'completed':
    case 'complete':
      return <StatusIndicator type="success">Completed</StatusIndicator>;
    case 'failed':
      return <StatusIndicator type="error">Failed</StatusIndicator>;
    case 'in_progress':
    case 'in-progress':
    case 'running':
      return <StatusIndicator type="in-progress">In progress</StatusIndicator>;
    case 'pending':
      return <StatusIndicator type="pending">Pending</StatusIndicator>;
    case 'abandoned':
      return <StatusIndicator type="warning">Abandoned</StatusIndicator>;
    default:
      return <StatusIndicator type="info">{status || '—'}</StatusIndicator>;
  }
}

// Versions without a completed dashboard should open the live progress
// page; if the backend enriches the row with an active run_id we can route
// there directly, otherwise the version has been abandoned.
function isLiveVersion(version) {
  return (
    version &&
    (version.status === 'in-progress' ||
      version.status === 'in_progress' ||
      version.status === 'running' ||
      version.status === 'pending') &&
    Boolean(version.run_id)
  );
}

// Abandoned versions have no output artefact and no live run — typically a
// crashed or interrupted scan from a prior server session. We render them as
// non-clickable so the user doesn't hit a 404 trying to open them.
function isAbandonedVersion(version) {
  return (
    version &&
    (version.status === 'abandoned' ||
      ((version.status === 'in-progress' ||
        version.status === 'in_progress' ||
        version.status === 'running' ||
        version.status === 'pending') &&
        !version.run_id))
  );
}

export default function AppOverviewPage() {
  const { appId } = useParams();
  const navigate = useNavigate();

  const [app, setApp] = useState(null);
  const [versions, setVersions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Rename modal
  const [renaming, setRenaming] = useState(false);
  const [renameDraft, setRenameDraft] = useState('');
  const [renameError, setRenameError] = useState('');
  const [renameSubmitting, setRenameSubmitting] = useState(false);

  // Project path modal — only available while the app has zero runs on disk.
  const [editingPath, setEditingPath] = useState(false);
  const [pathDraft, setPathDraft] = useState('');
  const [pathError, setPathError] = useState('');
  const [pathSubmitting, setPathSubmitting] = useState(false);

  // Delete modal
  const [deleting, setDeleting] = useState(false);
  const [deleteSubmitting, setDeleteSubmitting] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  // Delete-version modal. ``versionDeleteTarget`` doubles as the modal's
  // visibility flag — null means closed.
  const [versionDeleteTarget, setVersionDeleteTarget] = useState(null);
  // Surfaces fetch / generation failures from the per-row export menu so
  // they don't get lost in the toolbar.
  const [exportError, setExportError] = useState('');
  const [versionDeleteSubmitting, setVersionDeleteSubmitting] = useState(false);
  const [versionDeleteError, setVersionDeleteError] = useState('');

  // ThreatForest Report export modal — page-level button, scope is either
  // "version" (latest) or "full".
  const [reportPrompt, setReportPrompt] = useState(null);
  const [reportIncludeContext, setReportIncludeContext] = useState(true);
  const [reportSubmitting, setReportSubmitting] = useState(false);

  const loadAll = useCallback(
    async (signal) => {
      setLoading(true);
      setError(null);
      try {
        // Persistent record + folder-derived version list are independent
        // resources, so they fan out in parallel. Imported apps lack a
        // persistent record entirely (the importer doesn't write to
        // applications.json), so a 404 on getApplication falls back to a
        // minimal stub built from the apps-list summary — that's enough to
        // render the page in read-only mode.
        const [appResult, versionsData] = await Promise.all([
          getApplication(appId).catch((err) => ({ __error: err })),
          getApplicationVersions(appId).catch(() => ({ versions: [] })),
        ]);
        if (signal?.aborted) return;

        if (appResult?.__error) {
          // Try the folder-derived listing for an imported-app summary.
          let stub = null;
          try {
            const list = await getApplications();
            stub = (list?.applications || []).find((a) => a.id === appId) || null;
          } catch {
            // Ignore — we'll surface the original error if no stub exists.
          }
          if (stub) {
            setApp({
              id: stub.id,
              name: stub.name,
              description: stub.description,
              imported: stub.imported,
              imported_from: stub.imported_from,
              project_path: '',
              // Imported apps may still carry a business context — the
              // registry surfaces the sidecar JSON written at import time
              // alongside the apps-list summary.
              business_context: stub.business_context || null,
            });
          } else {
            throw appResult.__error;
          }
        } else {
          setApp(appResult);
        }
        setVersions(versionsData.versions || []);
      } catch (err) {
        if (signal?.aborted) return;
        setError(err.message || 'Failed to load application.');
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [appId]
  );

  useEffect(() => {
    const controller = new AbortController();
    loadAll(controller.signal);
    return () => controller.abort();
  }, [loadAll]);

  const sortedVersions = [...versions].sort((a, b) => {
    const at = a.run_date ? new Date(a.run_date).getTime() : 0;
    const bt = b.run_date ? new Date(b.run_date).getTime() : 0;
    return bt - at;
  });
  // "Latest threat model" should reflect the latest *usable* run — a completed
  // model the user can open, or a live run they can resume. Crashed/abandoned
  // versions get skipped because the link routes to a dashboard that will
  // never render. Falls back to the most recent abandoned version only when
  // nothing else exists, so users still see *something* and can clean it up.
  const latestVersion =
    sortedVersions.find((v) => !isAbandonedVersion(v)) || sortedVersions[0] || null;

  const handleBusinessContextUpdated = (updatedApp) => {
    setApp(updatedApp);
  };

  const openRename = () => {
    setRenameDraft(app?.name || '');
    setRenameError('');
    setRenaming(true);
  };

  const handleRenameSave = async () => {
    const name = renameDraft.trim();
    if (!name) {
      setRenameError('Name cannot be empty.');
      return;
    }
    if (name === app?.name) {
      setRenaming(false);
      return;
    }
    setRenameSubmitting(true);
    setRenameError('');
    try {
      const updated = await updateApplication(appId, { name });
      setApp(updated);
      setRenaming(false);
    } catch (err) {
      setRenameError(err.message || 'Failed to rename application.');
    } finally {
      setRenameSubmitting(false);
    }
  };

  const openPathEdit = () => {
    setPathDraft(app?.project_path || '');
    setPathError('');
    setEditingPath(true);
  };

  const handlePathSave = async () => {
    const projectPath = pathDraft.trim();
    if (!projectPath) {
      setPathError('Project path cannot be empty.');
      return;
    }
    if (projectPath === app?.project_path) {
      setEditingPath(false);
      return;
    }
    setPathSubmitting(true);
    setPathError('');
    try {
      const updated = await updateApplication(appId, { projectPath });
      setApp(updated);
      setEditingPath(false);
    } catch (err) {
      setPathError(err.message || 'Failed to update project path.');
    } finally {
      setPathSubmitting(false);
    }
  };

  const handleDelete = async () => {
    setDeleteSubmitting(true);
    setDeleteError('');
    try {
      await deleteApplicationRecord(appId);
      navigate('/applications');
    } catch (err) {
      setDeleteError(err.message || 'Failed to delete application.');
      setDeleteSubmitting(false);
    }
  };

  const handleReportExport = async () => {
    if (!reportPrompt) return;
    setReportSubmitting(true);
    setExportError('');
    try {
      await downloadThreatforestReport({
        appId,
        // ``version`` mode targets the latest *completed* version explicitly so
        // the URL doesn't accidentally bundle an in-progress run.
        versionId:
          reportPrompt === 'version' && latestVersion ? latestVersion.id : undefined,
        includeScannerContext: reportIncludeContext,
      });
      setReportPrompt(null);
    } catch (err) {
      setExportError(err.message || 'Failed to export ThreatForest Report.');
    } finally {
      setReportSubmitting(false);
    }
  };

  const handleVersionDelete = async () => {
    if (!versionDeleteTarget) return;
    setVersionDeleteSubmitting(true);
    setVersionDeleteError('');
    try {
      await deleteApplicationVersion(appId, versionDeleteTarget.id);
      // Optimistically drop the row rather than refetching — the backend has
      // already removed the folder and any follow-up fetch would just confirm
      // the same state.
      setVersions((prev) => prev.filter((v) => v.id !== versionDeleteTarget.id));
      setVersionDeleteTarget(null);
    } catch (err) {
      setVersionDeleteError(err.message || 'Failed to delete threat model.');
    } finally {
      setVersionDeleteSubmitting(false);
    }
  };

  const appName = app?.name || appId;

  // Imported applications are read-only — the recipient has no source code,
  // so re-running, editing the project path, or editing the business context
  // makes no sense. We hide those affordances instead of letting users click
  // them and hit a backend error. The flag is set by the apps-list endpoint
  // when the folder's metadata.json carries an ``imported_from_app_id``.
  const isImported = Boolean(app?.imported);
  const hasCompletedVersion = sortedVersions.some(
    (v) => v.status === 'complete' || v.status === 'completed'
  );

  if (loading) {
    return (
      <CloudscapeShell
        activePage="/applications"
        breadcrumbs={[
          { text: 'Home', href: '/' },
          { text: 'Applications', href: '/applications' },
          { text: appName, href: `/applications/${appId}` },
        ]}
      >
        <Box textAlign="center" padding="l" data-testid="loading-spinner">
          <Spinner size="large" />
        </Box>
      </CloudscapeShell>
    );
  }

  return (
    <CloudscapeShell
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: appName, href: `/applications/${appId}` },
      ]}
    >
      <SpaceBetween size="l">
        {error && (
          <Alert type="error" header="Error loading application">
            {error}
          </Alert>
        )}

        <Header
          variant="h1"
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              {!isImported && (
                <Button
                  iconName="edit"
                  onClick={openRename}
                  ariaLabel="Rename application"
                  data-testid="rename-app"
                />
              )}
              <Button
                onClick={() => {
                  const el = document.getElementById('threat-models');
                  if (el) el.scrollIntoView({ behavior: 'smooth' });
                }}
              >
                Jump to threat models
              </Button>
              {hasCompletedVersion && (
                <ButtonDropdown
                  items={[
                    { id: 'tfreport-version', text: 'Latest version only' },
                    { id: 'tfreport-full', text: 'Full application history' },
                  ]}
                  onItemClick={({ detail }) => {
                    setReportIncludeContext(true);
                    setReportPrompt(detail.id === 'tfreport-version' ? 'version' : 'full');
                  }}
                  data-testid="export-tfreport-button"
                >
                  Export ThreatForest Report
                </ButtonDropdown>
              )}
              {!isImported && (
                <Button
                  variant="primary"
                  onClick={() => navigate(`/applications/${appId}/runs/new`)}
                  data-testid="start-new-threat-model"
                >
                  Start new threat model
                </Button>
              )}
            </SpaceBetween>
          }
        >
          {appName}
        </Header>

        {isImported && (
          <Alert
            type="info"
            header="Imported application"
            data-testid="imported-banner"
          >
            This application was imported from{' '}
            <strong>{app?.imported_from || 'another ThreatForest install'}</strong>.
            The source code is not available here, so re-running and editing
            the business context are disabled. You can still browse threat
            models, edit mitigation status, and export.
          </Alert>
        )}

        {app && app.business_context && (
          <BusinessContextPanel
            appId={appId}
            businessContext={app.business_context}
            onUpdated={handleBusinessContextUpdated}
            readOnly={isImported}
          />
        )}

        {app && !isImported && (
          <Container
            header={
              <Header
                variant="h2"
                description="Edit the path whenever the repository is moved or renamed. Existing threat models stay attached to this application regardless of where the code lives now. Tip: point this only at the same codebase — a path belonging to a different application will produce misleading future threat models."
                actions={
                  <Button
                    iconName="edit"
                    onClick={openPathEdit}
                    ariaLabel="Edit project repository"
                    data-testid="edit-project-path"
                  />
                }
              >
                Project repository
              </Header>
            }
          >
            <Box variant="awsui-key-label">Path</Box>
            <Box data-testid="project-path-value">{app.project_path}</Box>
          </Container>
        )}

        <Container header={<Header variant="h2">Latest threat model</Header>}>
          {latestVersion ? (
            <ColumnLayout columns={3} variant="text-grid">
              <div>
                <Box variant="awsui-key-label">Threat model</Box>
                {isAbandonedVersion(latestVersion) ? (
                  <Box color="text-status-inactive">
                    {latestVersion.display_name || latestVersion.id}
                  </Box>
                ) : (
                  <Link
                    onFollow={(e) => {
                      e.preventDefault();
                      if (isLiveVersion(latestVersion)) {
                        navigate(`/runs/${latestVersion.run_id}/progress`);
                      } else {
                        // Use the explicit version id rather than the "latest"
                        // alias so the URL reflects what's open and survives
                        // future runs landing on top.
                        navigate(`/applications/${appId}/versions/${latestVersion.id}`);
                      }
                    }}
                  >
                    {latestVersion.display_name || latestVersion.id}
                  </Link>
                )}
              </div>
              <div>
                <Box variant="awsui-key-label">Run date</Box>
                <div>
                  {latestVersion.run_date
                    ? new Date(latestVersion.run_date).toLocaleString()
                    : '—'}
                </div>
              </div>
              <div>
                <Box variant="awsui-key-label">Status</Box>
                <div>{renderStatus(latestVersion.status)}</div>
              </div>
            </ColumnLayout>
          ) : (
            <Box textAlign="center" color="inherit" padding="m">
              <SpaceBetween size="m">
                <b>No threat models yet</b>
                {!isImported && (
                  <>
                    <Box color="inherit">
                      Start one to generate threats, attack trees, and
                      mitigations for this application.
                    </Box>
                    <Button
                      variant="primary"
                      onClick={() => navigate(`/applications/${appId}/runs/new`)}
                    >
                      Start new threat model
                    </Button>
                  </>
                )}
              </SpaceBetween>
            </Box>
          )}
        </Container>

        <div id="threat-models">
          {exportError && (
            <Alert
              type="error"
              dismissible
              onDismiss={() => setExportError('')}
              header="Export failed"
            >
              {exportError}
            </Alert>
          )}
          <Table
            columnDefinitions={[
              {
                id: 'version_id',
                header: 'Threat model',
                cell: (item) => {
                  const isLatest = item.id === latestVersion?.id;
                  const live = isLiveVersion(item);
                  const abandoned = isAbandonedVersion(item);
                  const label = item.display_name || item.id;
                  const displayLabel = isLatest ? `${label} (latest)` : label;
                  if (abandoned) {
                    // Non-clickable: there is nothing to render for an
                    // abandoned run. Keep the label so the user can still
                    // correlate with timestamps.
                    return (
                      <Box color="text-status-inactive">{displayLabel}</Box>
                    );
                  }
                  // Always use the explicit version id, even for the "latest"
                  // row. The /versions/latest alias would resolve server-side
                  // to whatever's most recent on disk at click-time, which can
                  // shift if a new run lands between render and click.
                  const target = live
                    ? `/runs/${item.run_id}/progress`
                    : `/applications/${appId}/versions/${item.id}`;
                  return (
                    <Link
                      onFollow={(e) => {
                        e.preventDefault();
                        navigate(target);
                      }}
                    >
                      {displayLabel}
                    </Link>
                  );
                },
              },
              {
                id: 'run_date',
                header: 'Run date',
                cell: (item) =>
                  item.run_date ? new Date(item.run_date).toLocaleDateString() : '—',
              },
              {
                id: 'status',
                header: 'Status',
                cell: (item) => renderStatus(item.status),
              },
              {
                id: 'high_severity_count',
                header: 'High-severity threats',
                cell: (item) => item.high_severity_count ?? 0,
              },
              {
                id: 'actions',
                header: 'Actions',
                cell: (item) => {
                  // Don't let the user delete a live run out from under an
                  // in-flight pipeline — the backend will 400 anyway, but
                  // hiding the control entirely avoids confusion. Likewise,
                  // exports need a completed dashboard to read from, so
                  // disable for live and abandoned rows.
                  const live = isLiveVersion(item);
                  const abandoned = isAbandonedVersion(item);
                  return (
                    <SpaceBetween direction="horizontal" size="xs">
                      <VersionRowExportMenu
                        appId={appId}
                        appName={app?.name}
                        version={item}
                        disabled={live || abandoned}
                        onError={setExportError}
                      />
                      <Button
                        variant="inline-link"
                        onClick={() => {
                          setVersionDeleteError('');
                          setVersionDeleteTarget(item);
                        }}
                        disabled={live}
                        data-testid={`delete-version-${item.id}`}
                      >
                        Delete
                      </Button>
                    </SpaceBetween>
                  );
                },
              },
            ]}
            items={sortedVersions}
            header={<Header variant="h2">Threat models</Header>}
            empty={
              <Box textAlign="center" color="inherit" padding="l">
                <SpaceBetween size="m">
                  <b>No threat models yet</b>
                  <Box color="inherit">
                    Run an analysis to create the first threat model.
                  </Box>
                </SpaceBetween>
              </Box>
            }
          />
        </div>

        <ExpandableSection
          variant="container"
          headerText="Advanced"
          headerDescription="Destructive actions. Collapsed by default to prevent accidental clicks."
        >
          <SpaceBetween size="s">
            <Box variant="h3">Delete application</Box>
            <Box variant="p">
              Permanently removes this application record and its threat model history
              from the console. This cannot be undone.
            </Box>
            <Button
              onClick={() => {
                setDeleteError('');
                setDeleting(true);
              }}
              data-testid="delete-app"
            >
              Delete application
            </Button>
          </SpaceBetween>
        </ExpandableSection>

        {/* Rename modal */}
        <Modal
          visible={renaming}
          onDismiss={() => setRenaming(false)}
          header="Rename application"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="link"
                  onClick={() => setRenaming(false)}
                  disabled={renameSubmitting}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleRenameSave}
                  loading={renameSubmitting}
                  data-testid="save-rename"
                >
                  Save
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <FormField label="New name" errorText={renameError}>
            <Input
              value={renameDraft}
              onChange={({ detail }) => {
                setRenameDraft(detail.value);
                if (detail.value.trim()) setRenameError('');
              }}
              autoFocus
              data-testid="rename-input"
            />
          </FormField>
        </Modal>

        {/* Project path modal */}
        <Modal
          visible={editingPath}
          onDismiss={() => !pathSubmitting && setEditingPath(false)}
          header="Edit project repository"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="link"
                  onClick={() => setEditingPath(false)}
                  disabled={pathSubmitting}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handlePathSave}
                  loading={pathSubmitting}
                  data-testid="save-project-path"
                >
                  Save
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <FormField
            label="Project repository path"
            description="Absolute path to the repository ThreatForest scans for this application. Use this when the repo has been moved or renamed — don't point it at a different application's codebase, or future threat models will drift from past runs."
            errorText={pathError}
          >
            <DirectoryPicker
              value={pathDraft}
              onChange={(v) => {
                setPathDraft(v);
                if (v.trim()) setPathError('');
              }}
              inputTestId="project-path-input"
            />
          </FormField>
        </Modal>

        {/* Delete modal */}
        <Modal
          visible={deleting}
          onDismiss={() => !deleteSubmitting && setDeleting(false)}
          header="Delete application"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="link"
                  onClick={() => setDeleting(false)}
                  disabled={deleteSubmitting}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleDelete}
                  loading={deleteSubmitting}
                  data-testid="confirm-delete"
                >
                  Delete
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="s">
            {deleteError && <Alert type="error">{deleteError}</Alert>}
            <Box variant="p">
              Are you sure you want to delete <strong>{appName}</strong>? This
              removes the application record but keeps run artefacts on disk.
            </Box>
          </SpaceBetween>
        </Modal>

        {/* Delete-version modal */}
        <Modal
          visible={versionDeleteTarget !== null}
          onDismiss={() =>
            !versionDeleteSubmitting && setVersionDeleteTarget(null)
          }
          header="Delete threat model"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="link"
                  onClick={() => setVersionDeleteTarget(null)}
                  disabled={versionDeleteSubmitting}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleVersionDelete}
                  loading={versionDeleteSubmitting}
                  data-testid="confirm-delete-version"
                >
                  Delete
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="s">
            {versionDeleteError && (
              <Alert type="error">{versionDeleteError}</Alert>
            )}
            <Box variant="p">
              Are you sure you want to delete{' '}
              <strong>
                {versionDeleteTarget?.display_name || versionDeleteTarget?.id}
              </strong>
              ? The threat statements, attack trees, and dashboard for this run
              will be removed from disk. This cannot be undone.
            </Box>
          </SpaceBetween>
        </Modal>

        {/* ThreatForest Report export modal */}
        <Modal
          visible={reportPrompt !== null}
          onDismiss={() => !reportSubmitting && setReportPrompt(null)}
          header="Export ThreatForest Report"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="link"
                  onClick={() => setReportPrompt(null)}
                  disabled={reportSubmitting}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleReportExport}
                  loading={reportSubmitting}
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
              Bundles{' '}
              {reportPrompt === 'full'
                ? 'every completed threat model for this application'
                : 'the latest completed threat model'}{' '}
              as a <code>.tfreport</code> file. Recipients can drop it into
              their <code>.threatforest/imports/</code> folder to load this
              application into their own ThreatForest install. Imported
              applications are read-only.
            </Box>
            <Toggle
              checked={reportIncludeContext}
              onChange={({ detail }) => setReportIncludeContext(detail.checked)}
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
      </SpaceBetween>
    </CloudscapeShell>
  );
}
