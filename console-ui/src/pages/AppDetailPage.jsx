import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Table from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Link from '@cloudscape-design/components/link';
import Spinner from '@cloudscape-design/components/spinner';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Container from '@cloudscape-design/components/container';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Badge from '@cloudscape-design/components/badge';
import CloudscapeShell from '../components/CloudscapeShell';
import { getApplicationVersions } from '../api-client';

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

function ProjectOverview({ projectInfo }) {
  if (!projectInfo) return null;
  const pi = projectInfo;
  const techs = Array.isArray(pi.technologies) ? pi.technologies : [];
  return (
    <Container header={<Header variant="h2">📋 Project Information</Header>}>
      <SpaceBetween size="m">
        <ColumnLayout columns={2} variant="text-grid">
          <div><Box variant="awsui-key-label">Application Name</Box><div>{pi.application_name || '—'}</div></div>
          <div><Box variant="awsui-key-label">Architecture Type</Box><div>{pi.architecture_type || '—'}</div></div>
          <div><Box variant="awsui-key-label">Deployment Environment</Box><div>{pi.deployment_environment || '—'}</div></div>
          <div><Box variant="awsui-key-label">Industry Sector</Box><div>{pi.sector || '—'}</div></div>
        </ColumnLayout>
        {techs.length > 0 && (
          <div>
            <Box variant="awsui-key-label">Technology Stack</Box>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '6px' }}>
              {techs.map((t, i) => <Badge key={i} color="grey">{t}</Badge>)}
            </div>
          </div>
        )}
      </SpaceBetween>
    </Container>
  );
}

export default function AppDetailPage() {
  const { appId } = useParams();
  const navigate = useNavigate();
  const [versions, setVersions] = useState([]);
  const [appName, setAppName] = useState(appId);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sortingColumn, setSortingColumn] = useState({ sortingField: 'run_date' });
  const [sortingDescending, setSortingDescending] = useState(true);
  const [projectInfo, setProjectInfo] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchVersions() {
      try {
        setLoading(true);
        setError(null);
        const data = await getApplicationVersions(appId);
        if (!cancelled) {
          setVersions(data.versions || []);
          if (data.application_name) setAppName(data.application_name);
        }
      } catch (err) {
        if (!cancelled) setError(err.message || 'Failed to load versions');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchVersions();
    // Also fetch project info from the latest version data
    fetch(`/api/applications/${encodeURIComponent(appId)}/versions/latest/data`)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (!cancelled && data?.project_info) setProjectInfo(data.project_info); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [appId]);

  const sortedVersions = [...versions].sort((a, b) => {
    const field = sortingColumn?.sortingField;
    if (!field) return 0;
    let cmp = 0;
    if (field === 'run_date') {
      cmp = (a.run_date ? new Date(a.run_date).getTime() : 0) - (b.run_date ? new Date(b.run_date).getTime() : 0);
    } else if (field === 'id') {
      cmp = (a.id || '').localeCompare(b.id || '');
    }
    return sortingDescending ? -cmp : cmp;
  });

  // API returns VersionSummary with field "id" (not "version_id")
  const columnDefinitions = [
    {
      id: 'version_id',
      header: 'Version ID',
      sortingField: 'id',
      cell: (item) => (
        <Link onFollow={(e) => {
          e.preventDefault();
          navigate(`/applications/${appId}/versions/${item.id}`);
        }}>
          {item.id}
        </Link>
      ),
    },
    {
      id: 'run_date',
      header: 'Run date',
      sortingField: 'run_date',
      cell: (item) => item.run_date ? new Date(item.run_date).toLocaleDateString() : '—',
    },
    {
      id: 'status',
      header: 'Status',
      cell: (item) => renderStatus(item.status),
    },
    {
      id: 'threat_count',
      header: 'High-level threats',
      cell: (item) => item.threat_count ?? 0,
    },
  ];

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
        <Header variant="h1">{appName}</Header>
        {error && <Alert type="error" header="Error loading versions">{error}</Alert>}
        {projectInfo && <ProjectOverview projectInfo={projectInfo} />}
        {loading ? (
          <Box textAlign="center" padding="l" data-testid="loading-spinner"><Spinner size="large" /></Box>
        ) : (
          <Table
            columnDefinitions={columnDefinitions}
            items={sortedVersions}
            sortingColumn={sortingColumn}
            sortingDescending={sortingDescending}
            onSortingChange={({ detail }) => {
              setSortingColumn(detail.sortingColumn);
              setSortingDescending(detail.isDescending);
            }}
            header={<Header variant="h2">Threat Model Versions</Header>}
            empty={
              <Box textAlign="center" color="inherit" padding="l">
                <SpaceBetween size="m">
                  <b>No versions</b>
                  <Box color="inherit">
                    No versions found.{' '}
                    <Link onFollow={(e) => { e.preventDefault(); navigate('/new-run'); }}>Start a new run</Link> to create one.
                  </Box>
                </SpaceBetween>
              </Box>
            }
          />
        )}
      </SpaceBetween>
    </CloudscapeShell>
  );
}
