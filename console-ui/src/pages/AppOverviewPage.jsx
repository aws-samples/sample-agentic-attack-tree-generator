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
import CloudscapeShell from '../components/CloudscapeShell';
import BusinessContextPanel from '../components/BusinessContextPanel';
import DirectoryPicker from '../components/DirectoryPicker';
import {
  getApplication,
  getApplicationVersions,
  updateApplication,
  deleteApplicationRecord,
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
    case 'running':
      return <StatusIndicator type="in-progress">In progress</StatusIndicator>;
    case 'pending':
      return <StatusIndicator type="pending">Pending</StatusIndicator>;
    default:
      return <StatusIndicator type="info">{status || '—'}</StatusIndicator>;
  }
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

  const loadAll = useCallback(
    async (signal) => {
      setLoading(true);
      setError(null);
      try {
        // Parallel fetch — the persistent record and the folder-derived
        // version list are independent resources.
        const [appData, versionsData] = await Promise.all([
          getApplication(appId),
          getApplicationVersions(appId).catch(() => ({ versions: [] })),
        ]);
        if (signal?.aborted) return;
        setApp(appData);
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
  const latestVersion = sortedVersions[0] || null;

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

  const appName = app?.name || appId;

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
              <Button
                iconName="edit"
                onClick={openRename}
                ariaLabel="Rename application"
                data-testid="rename-app"
              />
              <Button
                onClick={() => {
                  const el = document.getElementById('version-history');
                  if (el) el.scrollIntoView({ behavior: 'smooth' });
                }}
              >
                View all versions
              </Button>
              <Button
                variant="primary"
                onClick={() => navigate(`/applications/${appId}/runs/new`)}
                data-testid="start-new-threat-model"
              >
                Start new threat model
              </Button>
            </SpaceBetween>
          }
        >
          {appName}
        </Header>

        {app && (
          <BusinessContextPanel
            appId={appId}
            businessContext={app.business_context}
            onUpdated={handleBusinessContextUpdated}
          />
        )}

        {app && (
          <Container
            header={
              <Header
                variant="h2"
                description={
                  versions.length > 0
                    ? 'The project repository is locked after the first threat model run so existing versions stay tied to the same code.'
                    : 'Edit the project repository path. This is only available until the first threat model run.'
                }
                actions={
                  <Button
                    iconName="edit"
                    onClick={openPathEdit}
                    ariaLabel="Edit project repository"
                    data-testid="edit-project-path"
                    disabled={versions.length > 0}
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
                <Box variant="awsui-key-label">Version</Box>
                <Link
                  onFollow={(e) => {
                    e.preventDefault();
                    navigate(`/applications/${appId}/versions/latest`);
                  }}
                >
                  {latestVersion.display_name || latestVersion.id}
                </Link>
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
                <Box color="inherit">
                  Start one to generate threats, attack trees, and mitigations for this
                  application.
                </Box>
                <Button
                  variant="primary"
                  onClick={() => navigate(`/applications/${appId}/runs/new`)}
                >
                  Start new threat model
                </Button>
              </SpaceBetween>
            </Box>
          )}
        </Container>

        <div id="version-history">
          <Table
            columnDefinitions={[
              {
                id: 'version_id',
                header: 'Version',
                cell: (item) => {
                  const isLatest = item.id === latestVersion?.id;
                  const target = isLatest
                    ? `/applications/${appId}/versions/latest`
                    : `/applications/${appId}/versions/${item.id}`;
                  return (
                    <Link
                      onFollow={(e) => {
                        e.preventDefault();
                        navigate(target);
                      }}
                    >
                      {(() => {
                        const label = item.display_name || item.id;
                        return isLatest ? `${label} (latest)` : label;
                      })()}
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
            ]}
            items={sortedVersions}
            header={<Header variant="h2">Version history</Header>}
            empty={
              <Box textAlign="center" color="inherit" padding="l">
                <SpaceBetween size="m">
                  <b>No versions</b>
                  <Box color="inherit">
                    Start a threat model to create the first version.
                  </Box>
                </SpaceBetween>
              </Box>
            }
          />
        </div>

        <Container
          header={
            <Header variant="h2" description="Permanent — deleted applications cannot be recovered.">
              Danger zone
            </Header>
          }
        >
          <SpaceBetween size="s">
            <Box variant="p">
              Delete this application record. Run artefacts on disk are kept so
              you can re-import them later if needed.
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
        </Container>

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
            description="Absolute path to the repository ThreatForest scans for this application."
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
      </SpaceBetween>
    </CloudscapeShell>
  );
}
