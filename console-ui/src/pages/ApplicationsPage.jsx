import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Table from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import Button from '@cloudscape-design/components/button';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import Modal from '@cloudscape-design/components/modal';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Link from '@cloudscape-design/components/link';
import Spinner from '@cloudscape-design/components/spinner';
import CloudscapeShell from '../components/CloudscapeShell';
import { getApplications, deleteApplication } from '../api-client';
import { exportCsv, exportPdf } from '../utils/export-service';

const EXPORT_ITEMS = [
  { id: 'export-pdf', text: 'Export PDF' },
  { id: 'export-csv', text: 'Export CSV' },
];

function AppExportButton({ appId }) {
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState(null);

  async function handleExport({ detail }) {
    setError(null);
    setExporting(true);
    try {
      const response = await fetch(
        `/api/applications/${encodeURIComponent(appId)}/versions/latest/data`
      );
      if (!response.ok) throw new Error(`Failed to fetch data (HTTP ${response.status})`);
      const data = await response.json();
      const attackTree = data?.attack_trees?.[0];
      if (!attackTree || !Array.isArray(attackTree.attack_steps) || attackTree.attack_steps.length === 0) {
        setError('No attack tree data available to export.');
        return;
      }
      const filename = `attack-tree-${appId}`;
      if (detail.id === 'export-csv') {
        exportCsv(attackTree, `${filename}.csv`);
      } else if (detail.id === 'export-pdf') {
        exportPdf(attackTree, data, `${filename}.pdf`);
      }
    } catch (err) {
      setError(err.message || 'Export failed');
    } finally {
      setExporting(false);
    }
  }

  return (
    <SpaceBetween size="xs">
      {error && (
        <Alert type="error" dismissible onDismiss={() => setError(null)} data-testid={`export-error-${appId}`}>
          {error}
        </Alert>
      )}
      <ButtonDropdown
        items={EXPORT_ITEMS}
        onItemClick={handleExport}
        loading={exporting}
        variant="inline-icon"
        data-testid={`export-button-${appId}`}
      >
        Export
      </ButtonDropdown>
    </SpaceBetween>
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
      await deleteApplication(deleteTarget.id);
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
      width: 180,
      cell: (item) => (
        <Link onFollow={(e) => { e.preventDefault(); navigate(`/applications/${item.id}`); }}>
          {item.name}
        </Link>
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
      cell: (item) => <AppExportButton appId={item.id} />,
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
            header={<Header description="Browse and manage your threat model applications">Applications</Header>}
            empty={
              <Box textAlign="center" color="inherit" padding="l">
                <SpaceBetween size="m">
                  <b>No applications</b>
                  <Box color="inherit">
                    No applications found.{' '}
                    <Link onFollow={(e) => { e.preventDefault(); navigate('/new-run'); }}>Start a new run</Link> to create one.
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
