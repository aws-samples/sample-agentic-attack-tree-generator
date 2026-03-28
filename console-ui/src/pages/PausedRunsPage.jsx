import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Table from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import Button from '@cloudscape-design/components/button';
import Modal from '@cloudscape-design/components/modal';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Link from '@cloudscape-design/components/link';
import CloudscapeShell from '../components/CloudscapeShell';
import { getPausedRuns, deletePausedRun, createRun } from '../api-client';

export default function PausedRunsPage() {
  const navigate = useNavigate();
  const [pausedRuns, setPausedRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleteError, setDeleteError] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [resumingId, setResumingId] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function fetch() {
      try {
        setLoading(true);
        setError(null);
        const data = await getPausedRuns();
        if (!cancelled) setPausedRuns(data.paused_runs || []);
      } catch (err) {
        if (!cancelled) setError(err.message || 'Failed to load paused runs');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetch();
    return () => { cancelled = true; };
  }, []);

  const handleResume = async (item) => {
    setResumingId(item.id);
    try {
      const config = item.config || {};
      const { run_id } = await createRun({
        project_path: config.project_path || item.project_path,
        threat_source: config.threat_source || 'auto',
        threat_file_path: config.threat_file_path || null,
        resume_run_dir: item.run_dir,
        skip_nodes: item.completed_nodes || [],
      });
      navigate(`/runs/${run_id}/progress`);
    } catch (err) {
      setError(`Failed to resume: ${err.message}`);
      setResumingId(null);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    try {
      setDeleting(true);
      setDeleteError(null);
      await deletePausedRun(deleteTarget.id);
      setPausedRuns((prev) => prev.filter((r) => r.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch (err) {
      setDeleteError(err.message || 'Failed to remove paused run');
    } finally {
      setDeleting(false);
    }
  };

  const columnDefinitions = [
    {
      id: 'name',
      header: 'Application',
      width: 200,
      cell: (item) => (
        <Link onFollow={(e) => { e.preventDefault(); handleResume(item); }}>
          {item.name}
        </Link>
      ),
    },
    {
      id: 'project_path',
      header: 'Project Path',
      width: 300,
      cell: (item) => (
        <div style={{ whiteSpace: 'normal', wordBreak: 'break-all' }}>
          {item.project_path || '—'}
        </div>
      ),
    },
    {
      id: 'completed_nodes',
      header: 'Completed Stages',
      width: 200,
      cell: (item) => (item.completed_nodes || []).join(', ') || '—',
    },
    {
      id: 'paused_at',
      header: 'Paused At',
      width: 160,
      cell: (item) => item.paused_at ? new Date(item.paused_at).toLocaleString() : '—',
    },
    {
      id: 'actions',
      header: 'Actions',
      width: 180,
      cell: (item) => (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <Button
            variant="inline-link"
            onClick={() => handleResume(item)}
            loading={resumingId === item.id}
            disabled={resumingId !== null}
          >
            Resume
          </Button>
          <span style={{ color: '#aab7b8' }}>|</span>
          <Button
            variant="inline-link"
            onClick={() => setDeleteTarget(item)}
            disabled={resumingId !== null}
          >
            Delete
          </Button>
        </span>
      ),
    },
  ];

  return (
    <CloudscapeShell
      activePage="/paused-runs"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Paused Runs', href: '/paused-runs' },
      ]}
    >
      <SpaceBetween size="l">
        {error && <Alert type="error" dismissible onDismiss={() => setError(null)}>{error}</Alert>}
        {deleteError && (
          <Alert type="error" dismissible onDismiss={() => setDeleteError(null)}>
            {deleteError}
          </Alert>
        )}
        {loading ? (
          <Box textAlign="center" padding="l"><Spinner size="large" /></Box>
        ) : (
          <Table
            wrapLines
            columnDefinitions={columnDefinitions}
            items={pausedRuns}
            header={
              <Header description="Applications with paused scans that can be resumed">
                Paused Runs
              </Header>
            }
            empty={
              <Box textAlign="center" color="inherit" padding="l">
                <SpaceBetween size="m">
                  <b>No paused runs</b>
                  <Box color="inherit">
                    There are no paused scans to resume.{' '}
                    <Link onFollow={(e) => { e.preventDefault(); navigate('/new-run'); }}>
                      Start a new run
                    </Link>
                  </Box>
                </SpaceBetween>
              </Box>
            }
          />
        )}
        <Modal
          visible={deleteTarget !== null}
          onDismiss={() => setDeleteTarget(null)}
          header="Remove paused run"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setDeleteTarget(null)}>Cancel</Button>
                <Button variant="primary" onClick={handleDeleteConfirm} loading={deleting}>
                  Delete
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          Remove the paused run for <strong>{deleteTarget?.name}</strong>? This will discard the
          pause state and the scan cannot be resumed.
        </Modal>
      </SpaceBetween>
    </CloudscapeShell>
  );
}
