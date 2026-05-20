import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Table from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import Button from '@cloudscape-design/components/button';
import Modal from '@cloudscape-design/components/modal';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Link from '@cloudscape-design/components/link';
import Spinner from '@cloudscape-design/components/spinner';
import Badge from '@cloudscape-design/components/badge';
import CloudscapeShell from '../components/CloudscapeShell';
import ImportReportButton from '../components/ImportReportButton';
import {
  getApplications,
  deleteApplicationRecord,
  deleteApplication,
} from '../api-client';
import { exportCustomPdf, exportCustomCsvBundle } from '../utils/export-service';
import CustomiseExportModal from '../components/CustomiseExportModal';

/**
 * Per-row export entry on the Applications table. Operates on the latest
 * completed version of an application; opens the same customise-export
 * modal used across the app so users see a consistent flow.
 *
 * The full ``/data`` blob is fetched lazily when the user clicks Export so
 * we don't pre-fetch for every app on the page.
 */
function AppExportButton({ appId, appName }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  async function handleClick() {
    setError(null);
    setOpen(true);
    setBusy(true);
    try {
      const response = await fetch(
        `/api/applications/${encodeURIComponent(appId)}/versions/latest/data`
      );
      if (!response.ok) {
        throw new Error(`Failed to fetch data (HTTP ${response.status})`);
      }
      setData(await response.json());
    } catch (err) {
      setError(err.message || 'Failed to load version data.');
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirm({ sections, format }) {
    if (!data) {
      setError('Version data not loaded yet — please wait.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const safeName = (appName || appId).replace(/\s+/g, '-').toLowerCase();
      const filename =
        format === 'pdf'
          ? `${safeName}-latest.pdf`
          : `${safeName}-latest.csv`;
      if (format === 'pdf') {
        exportCustomPdf(data, sections, filename);
      } else {
        await exportCustomCsvBundle(data, sections, filename);
      }
      setOpen(false);
    } catch (err) {
      setError(err.message || 'Failed to generate export.');
    } finally {
      setBusy(false);
    }
  }

  const threatCount = Array.isArray(data?.attack_trees)
    ? data.attack_trees.length
    : 0;

  return (
    <>
      <Button
        variant="inline-link"
        onClick={handleClick}
        loading={busy && !open}
        data-testid={`export-button-${appId}`}
      >
        Export
      </Button>
      <CustomiseExportModal
        visible={open}
        onDismiss={() => !busy && setOpen(false)}
        onConfirm={handleConfirm}
        loading={busy}
        error={error}
        threatCount={threatCount}
      />
    </>
  );
}

export default function ApplicationsPage() {
  const navigate = useNavigate();
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleteError, setDeleteError] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [sortingColumn, setSortingColumn] = useState({ sortingField: 'name' });
  const [sortingDescending, setSortingDescending] = useState(false);

  const refreshApps = async () => {
    try {
      setError(null);
      const data = await getApplications();
      setApplications(data.applications || []);
    } catch (err) {
      setError(err.message || 'Failed to load applications');
    }
  };

  useEffect(() => {
    let cancelled = false;
    async function fetchApps() {
      try {
        setLoading(true);
        setError(null);
        const data = await getApplications();
        if (!cancelled) setApplications(data.applications || []);
      } catch (err) {
        if (!cancelled) setError(err.message || 'Failed to load applications');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchApps();
    return () => { cancelled = true; };
  }, []);

  const sortedApplications = [...applications].sort((a, b) => {
    const field = sortingColumn?.sortingField;
    if (!field) return 0;
    let cmp = 0;
    if (field === 'name') cmp = (a.name || '').localeCompare(b.name || '');
    else if (field === 'last_run_date') {
      cmp = (a.last_run_date ? new Date(a.last_run_date).getTime() : 0) -
            (b.last_run_date ? new Date(b.last_run_date).getTime() : 0);
    }
    return sortingDescending ? -cmp : cmp;
  });

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    try {
      setDeleting(true);
      setDeleteError(null);
      // v2 persistent records carry an ``app_*`` id; legacy folder-derived
      // apps carry a slug. Dispatch to the right endpoint so both kinds
      // can be deleted from the same list view.
      if (String(deleteTarget.id || '').startsWith('app_')) {
        await deleteApplicationRecord(deleteTarget.id);
      } else {
        await deleteApplication(deleteTarget.id);
      }
      setApplications((prev) => prev.filter((app) => app.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch (err) {
      setDeleteError(err.message || 'Failed to delete application');
    } finally {
      setDeleting(false);
    }
  };

  const columnDefinitions = [
    {
      id: 'name',
      header: 'Application',
      sortingField: 'name',
      width: 220,
      cell: (item) => (
        <SpaceBetween direction="horizontal" size="xs">
          <Link onFollow={(e) => { e.preventDefault(); navigate(`/applications/${item.id}`); }}>
            {item.name}
          </Link>
          {item.imported && (
            <Badge
              color="blue"
              data-testid={`imported-badge-${item.id}`}
              title={
                item.imported_from
                  ? `Imported from ${item.imported_from} — read-only`
                  : 'Imported — read-only'
              }
            >
              Imported
            </Badge>
          )}
        </SpaceBetween>
      ),
    },
    {
      id: 'description',
      header: 'Description',
      width: 420,
      cell: (item) => (
        <div style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>
          {item.description || '—'}
        </div>
      ),
    },
    {
      id: 'version_count',
      header: 'Versions',
      width: 90,
      cell: (item) => item.version_count ?? 0,
    },
    {
      id: 'last_run_date',
      header: 'Last run',
      sortingField: 'last_run_date',
      width: 110,
      cell: (item) => item.last_run_date ? new Date(item.last_run_date).toLocaleDateString() : '—',
    },
    {
      id: 'dashboard',
      header: 'Dashboard',
      width: 100,
      cell: (item) => (
        <Link onFollow={(e) => {
          e.preventDefault();
          navigate(`/applications/${item.id}/versions/latest`);
        }}>View</Link>
      ),
    },
    {
      id: 'export',
      header: 'Export',
      width: 110,
      cell: (item) => <AppExportButton appId={item.id} appName={item.name} />,
    },
    {
      id: 'actions',
      header: 'Actions',
      width: 80,
      cell: (item) => (
        <Button variant="inline-link" onClick={() => setDeleteTarget(item)}>Delete</Button>
      ),
    },
  ];

  return (
    <CloudscapeShell
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
      ]}
    >
      <SpaceBetween size="l">
        {error && <Alert type="error" header="Error loading applications">{error}</Alert>}
        {deleteError && (
          <Alert type="error" header="Error deleting application" dismissible onDismiss={() => setDeleteError(null)}>
            {deleteError}
          </Alert>
        )}
        {loading ? (
          <Box textAlign="center" padding="l" data-testid="loading-spinner"><Spinner size="large" /></Box>
        ) : (
          <Table
            wrapLines
            columnDefinitions={columnDefinitions}
            items={sortedApplications}
            sortingColumn={sortingColumn}
            sortingDescending={sortingDescending}
            onSortingChange={({ detail }) => {
              setSortingColumn(detail.sortingColumn);
              setSortingDescending(detail.isDescending);
            }}
            header={
              <Header
                description="Browse and manage your threat model applications"
                actions={
                  <SpaceBetween direction="horizontal" size="xs">
                    <ImportReportButton onImported={refreshApps} />
                    <Button
                      variant="primary"
                      onClick={() => navigate('/applications/new')}
                      data-testid="create-application"
                    >
                      Create application
                    </Button>
                  </SpaceBetween>
                }
              >
                Applications
              </Header>
            }
            empty={
              <Box textAlign="center" color="inherit" padding="l">
                <SpaceBetween size="m">
                  <b>No applications</b>
                  <Box color="inherit">
                    No applications found.{' '}
                    <Link onFollow={(e) => { e.preventDefault(); navigate('/applications/new'); }}>Create an application</Link> to get started.
                  </Box>
                </SpaceBetween>
              </Box>
            }
          />
        )}
        <Modal
          visible={deleteTarget !== null}
          onDismiss={() => setDeleteTarget(null)}
          header="Delete application"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setDeleteTarget(null)}>Cancel</Button>
                <Button variant="primary" onClick={handleDeleteConfirm} loading={deleting}>Delete</Button>
              </SpaceBetween>
            </Box>
          }
        >
          Are you sure you want to delete <strong>{deleteTarget?.name}</strong>? This cannot be undone.
        </Modal>
      </SpaceBetween>
    </CloudscapeShell>
  );
}
