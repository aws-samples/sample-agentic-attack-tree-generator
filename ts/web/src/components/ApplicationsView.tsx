'use client';

/**
 * Shared applications list view.
 *
 * Rendered by BOTH the root route ("/") and "/applications" so the landing page
 * IS the applications list. The two callers differ only in shell chrome
 * (active nav item + breadcrumbs) and whether the active/paused-run banners are
 * surfaced — passed via props — so the table, sorting, per-row export, and
 * delete logic live in exactly one place.
 *
 * Previously "/" was a marketing landing page (hero + pipeline explainer + a
 * single context-aware CTA) that never showed the apps list; the run-resumption
 * affordances from that page are preserved here as the optional run banners.
 */

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Table, { type TableProps } from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import Button from '@cloudscape-design/components/button';
import Modal from '@cloudscape-design/components/modal';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Link from '@cloudscape-design/components/link';
import Spinner from '@cloudscape-design/components/spinner';
import Badge from '@cloudscape-design/components/badge';
import Container from '@cloudscape-design/components/container';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import type { ApplicationSummary, RunState } from '@threatforest/types';
import type { BreadcrumbGroupProps } from '@cloudscape-design/components/breadcrumb-group';
import AppShell from '@/components/AppShell';
import ImportReportButton from '@/components/ImportReportButton';
import CustomiseExportModal, {
  type CustomiseExportConfirm,
} from '@/components/CustomiseExportModal';
import {
  getApplications,
  getActiveRuns,
  getPausedRuns,
  deleteApplicationRecord,
  deleteApplication,
} from '@/api/client';
import {
  exportCustomPdf,
  exportCustomCsvBundle,
  type ThreatModelSummary,
} from '@/utils/export-service';

interface AppExportButtonProps {
  appId: string;
  appName?: string | null;
}

/**
 * Per-row export entry on the Applications table. Operates on the latest
 * completed version of an application; opens the same customise-export
 * modal used across the app so users see a consistent flow.
 *
 * The full ``/data`` blob is fetched lazily when the user clicks Export so
 * we don't pre-fetch for every app on the page.
 */
function AppExportButton({ appId, appName }: AppExportButtonProps) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState<ThreatModelSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleClick() {
    setError(null);
    setOpen(true);
    setBusy(true);
    try {
      const response = await fetch(
        `/api/applications/${encodeURIComponent(appId)}/versions/latest/data`,
      );
      if (!response.ok) {
        throw new Error(`Failed to fetch data (HTTP ${response.status})`);
      }
      setData((await response.json()) as ThreatModelSummary);
    } catch (err) {
      setError((err as Error).message || 'Failed to load version data.');
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirm({ sections, format }: CustomiseExportConfirm) {
    if (!data) {
      setError('Version data not loaded yet — please wait.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const safeName = (appName || appId).replace(/\s+/g, '-').toLowerCase();
      const filename = format === 'pdf' ? `${safeName}-latest.pdf` : `${safeName}-latest.csv`;
      if (format === 'pdf') {
        exportCustomPdf(data, sections, filename);
      } else {
        await exportCustomCsvBundle(data, sections, filename);
      }
      setOpen(false);
    } catch (err) {
      setError((err as Error).message || 'Failed to generate export.');
    } finally {
      setBusy(false);
    }
  }

  const threatCount = Array.isArray(data?.attack_trees) ? data!.attack_trees!.length : 0;

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

export interface ApplicationsViewProps {
  /** Side-nav href to highlight (``/`` on the home route, ``/applications`` otherwise). */
  activePage: string;
  /** Breadcrumb trail for the page. */
  breadcrumbs: BreadcrumbGroupProps.Item[];
  /**
   * When true, surface the active-runs and paused-runs banners above the table.
   * Used by the home route so the run-resumption affordances from the old
   * landing page aren't lost.
   */
  showRunBanners?: boolean;
}

export default function ApplicationsView({
  activePage,
  breadcrumbs,
  showRunBanners = false,
}: ApplicationsViewProps) {
  const router = useRouter();
  const [applications, setApplications] = useState<ApplicationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ApplicationSummary | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [sortingColumn, setSortingColumn] = useState<
    TableProps.SortingColumn<ApplicationSummary>
  >({ sortingField: 'name' });
  const [sortingDescending, setSortingDescending] = useState(false);

  // Run banners (home variant only).
  const [activeRuns, setActiveRuns] = useState<RunState[]>([]);
  const [pausedCount, setPausedCount] = useState(0);

  const refreshApps = async () => {
    try {
      setError(null);
      const data = await getApplications();
      setApplications(data.applications || []);
    } catch (err) {
      setError((err as Error).message || 'Failed to load applications');
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
        if (!cancelled) setError((err as Error).message || 'Failed to load applications');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchApps();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!showRunBanners) return;
    let cancelled = false;
    getActiveRuns()
      .then((data) => {
        if (!cancelled) setActiveRuns(data.runs || []);
      })
      .catch(() => {});
    getPausedRuns()
      .then((data) => {
        if (!cancelled) setPausedCount((data.paused_runs || []).length);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [showRunBanners]);

  const sortedApplications = [...applications].sort((a, b) => {
    const field = sortingColumn?.sortingField;
    if (!field) return 0;
    let cmp = 0;
    if (field === 'name') cmp = (a.name || '').localeCompare(b.name || '');
    else if (field === 'last_run_date') {
      cmp =
        (a.last_run_date ? new Date(a.last_run_date).getTime() : 0) -
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
      setDeleteError((err as Error).message || 'Failed to delete application');
    } finally {
      setDeleting(false);
    }
  };

  const columnDefinitions: ReadonlyArray<TableProps.ColumnDefinition<ApplicationSummary>> = [
    {
      id: 'name',
      header: 'Application',
      sortingField: 'name',
      width: 220,
      cell: (item) => (
        <SpaceBetween direction="horizontal" size="xs">
          <Link
            onFollow={(e) => {
              e.preventDefault();
              router.push(`/applications/${item.id}`);
            }}
          >
            {item.name}
          </Link>
          {item.imported && (
            <Badge
              color="blue"
              data-testid={`imported-badge-${item.id}`}
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
      cell: (item) =>
        item.last_run_date ? new Date(item.last_run_date).toLocaleDateString() : '—',
    },
    {
      id: 'dashboard',
      header: 'Dashboard',
      width: 100,
      cell: (item) => (
        <Link
          onFollow={(e) => {
            e.preventDefault();
            router.push(`/applications/${item.id}/versions/latest`);
          }}
        >
          View
        </Link>
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
        <Button variant="inline-link" onClick={() => setDeleteTarget(item)}>
          Delete
        </Button>
      ),
    },
  ];

  return (
    <AppShell activePage={activePage} breadcrumbs={breadcrumbs}>
      <SpaceBetween size="l">
        {showRunBanners && activeRuns.length > 0 && (
          <Container header={<Header variant="h2">Active runs</Header>}>
            <SpaceBetween size="s">
              {activeRuns.map((run) => (
                <Box key={run.run_id}>
                  <SpaceBetween direction="horizontal" size="s" alignItems="center">
                    <StatusIndicator type="in-progress">
                      {run.status === 'pending' ? 'Starting' : 'Running'}
                    </StatusIndicator>
                    <Box variant="span" color="text-body-secondary">
                      {run.config?.project_path?.split('/').pop() || run.run_id}
                    </Box>
                    <Link
                      onFollow={(e) => {
                        e.preventDefault();
                        router.push(`/runs/${run.run_id}/progress`);
                      }}
                    >
                      View progress
                    </Link>
                  </SpaceBetween>
                </Box>
              ))}
            </SpaceBetween>
          </Container>
        )}

        {error && (
          <Alert type="error" header="Error loading applications">
            {error}
          </Alert>
        )}
        {deleteError && (
          <Alert
            type="error"
            header="Error deleting application"
            dismissible
            onDismiss={() => setDeleteError(null)}
          >
            {deleteError}
          </Alert>
        )}
        {loading ? (
          <Box textAlign="center" padding="l" data-testid="loading-spinner">
            <Spinner size="large" />
          </Box>
        ) : (
          <Table
            wrapLines
            columnDefinitions={[...columnDefinitions]}
            items={sortedApplications}
            sortingColumn={sortingColumn}
            sortingDescending={sortingDescending}
            onSortingChange={({ detail }) => {
              setSortingColumn(detail.sortingColumn);
              setSortingDescending(detail.isDescending ?? false);
            }}
            header={
              <Header
                description="Browse and manage your threat model applications"
                counter={`(${applications.length})`}
                actions={
                  <SpaceBetween direction="horizontal" size="xs">
                    {showRunBanners && pausedCount > 0 && (
                      <Button onClick={() => router.push('/paused-runs')}>
                        Resume paused runs ({pausedCount})
                      </Button>
                    )}
                    <ImportReportButton onImported={refreshApps} />
                    <Button
                      variant="primary"
                      onClick={() => router.push('/applications/new')}
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
                    <Link
                      onFollow={(e) => {
                        e.preventDefault();
                        router.push('/applications/new');
                      }}
                    >
                      Create an application
                    </Link>{' '}
                    to get started.
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
                <Button variant="link" onClick={() => setDeleteTarget(null)}>
                  Cancel
                </Button>
                <Button variant="primary" onClick={handleDeleteConfirm} loading={deleting}>
                  Delete
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          Are you sure you want to delete <strong>{deleteTarget?.name}</strong>? This cannot be
          undone.
        </Modal>
      </SpaceBetween>
    </AppShell>
  );
}
