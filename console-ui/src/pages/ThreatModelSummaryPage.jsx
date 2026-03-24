import { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Box from '@cloudscape-design/components/box';
import Header from '@cloudscape-design/components/header';
import Alert from '@cloudscape-design/components/alert';
import Spinner from '@cloudscape-design/components/spinner';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Container from '@cloudscape-design/components/container';
import Badge from '@cloudscape-design/components/badge';
import Table from '@cloudscape-design/components/table';
import Button from '@cloudscape-design/components/button';
import Popover from '@cloudscape-design/components/popover';
import CloudscapeShell from '../components/CloudscapeShell';
import ExportButton from '../components/ExportButton';
import { aggregateMitigations } from '../utils/mitigation-aggregator';

function PriorityBadge({ priority }) {
  const p = (priority || '').toLowerCase();
  const colorMap = { high: 'red', critical: 'red', medium: 'blue', low: 'green' };
  return <Badge color={colorMap[p] || 'grey'}>{priority || '\u2014'}</Badge>;
}

function SummaryBar({ data, totalMitigations }) {
  const ext = data?.extraction_summary || {};
  const map = data?.mapping_summary || {};
  const stats = [
    { label: 'Total Threats', value: ext.total_threats ?? 0 },
    { label: 'High Severity', value: ext.high_severity_count ?? 0, color: '#d13212' },
    { label: 'Attack Trees', value: (data?.attack_trees || []).length },
    { label: 'TTP Mappings', value: map.total_mappings ?? 0 },
    { label: 'Mitigations', value: totalMitigations },
  ];
  return (
    <Container>
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${stats.length}, 1fr)` }}>
        {stats.map((s, i) => (
          <div key={i} style={{ textAlign: 'center' }}>
            <Box variant="awsui-key-label">{s.label}</Box>
            <div style={{ fontSize: '24px', fontWeight: 700, color: s.color || 'inherit' }}>{s.value}</div>
          </div>
        ))}
      </div>
    </Container>
  );
}

function MitigationsList({ mitigations }) {
  if (!mitigations || mitigations.length === 0) {
    return <Box color="text-status-inactive">No mitigations</Box>;
  }

  const PRIORITY_COLORS = { 1: 'red', 2: 'red', 3: 'blue', high: 'red', critical: 'red', medium: 'blue', low: 'grey' };
  const REMEDIATION_LABELS = {
    quick_win: { label: 'Quick Win', color: 'green' },
    short_term: { label: 'Short Term', color: 'blue' },
    medium_term: { label: 'Medium Term', color: 'blue' },
    long_term: { label: 'Long Term', color: 'grey' },
    monitoring: { label: 'Monitoring', color: 'grey' },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {mitigations.map((m, i) => {
        const rt = m.remediationType || m.remediation_type;
        const rtInfo = REMEDIATION_LABELS[rt] || null;
        return (
          <div key={i} style={{ padding: '8px 12px', background: '#fafafa', borderRadius: '6px', border: '1px solid #e9ebed' }}>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              {m.priority && <Badge color={PRIORITY_COLORS[m.priority] || 'grey'}>
                {typeof m.priority === 'number' ? ['', 'Critical', 'High', 'Medium', 'Low'][m.priority] || `P${m.priority}` : m.priority}
              </Badge>}
              {rtInfo && <Badge color={rtInfo.color}>{rtInfo.label}</Badge>}
            </div>
            <div style={{ marginTop: '4px', fontWeight: 500 }}>{m.name}</div>
          </div>
        );
      })}
    </div>
  );
}

export default function ThreatModelSummaryPage() {
  const { appId, versionId } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [appName, setAppName] = useState(appId);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchVersion() {
      try {
        setLoading(true); setError(null);
        const response = await fetch(`/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/data`);
        if (!response.ok) throw new Error(`Failed to load (HTTP ${response.status})`);
        const json = await response.json();
        if (cancelled) return;
        setData(json);
        if (json.project_info?.application_name) setAppName(json.project_info.application_name);
        else if (json.application_name) setAppName(json.application_name);
      } catch (err) {
        if (!cancelled) setError(err.message || 'Failed to load');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchVersion();
    return () => { cancelled = true; };
  }, [appId, versionId]);

  const attackTrees = data?.attack_trees || [];

  // Build table items — one row per attack tree (which maps 1:1 to a threat)
  // Use aggregateMitigations for deduplicated counts consistent with the attack tree view
  const tableItems = useMemo(() => {
    return attackTrees.map((tree, idx) => ({
      idx,
      threat_id: tree.threat_id || `Threat ${idx + 1}`,
      threat_category: tree.threat_category || 'Unknown',
      priority: tree.priority || '\u2014',
      threat_statement: tree.threat_statement || tree.threat_description || '',
      threatSource: tree.threatSource || '',
      affected_components: (() => {
        const threats = data?.threats || [];
        const matchId = (tree.threat_id || '').replace(/ \[AttackTree.*\]/, '');
        const match = threats.find(t => (t.id || t.threat_id) === matchId);
        return match?.affected_components || match?.impactedAssets || [];
      })(),
      mitigations: aggregateMitigations(tree),
      mapping_count: tree.mapping_count || (tree.ttc_mappings || []).length,
      step_count: (tree.attack_steps || []).length,
    }));
  }, [attackTrees, data]);

  // Total deduplicated mitigations across all trees
  const totalMitigations = useMemo(
    () => tableItems.reduce((sum, item) => sum + item.mitigations.length, 0),
    [tableItems]
  );

  const COLUMN_DEFINITIONS = [
    {
      id: 'threat_id',
      header: 'ID',
      cell: (item) => <span style={{ fontWeight: 600 }}>{item.threat_id}</span>,
      width: 120,
      sortingField: 'threat_id',
    },
    {
      id: 'threat_category',
      header: 'Title / Statement',
      cell: (item) => (
        <div style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>
          <div style={{ fontWeight: 500 }}>{item.threat_category}</div>
          {item.threat_statement && (
            <div style={{ fontSize: '12px', color: '#5f6b7a', marginTop: '2px' }}>
              {item.threat_statement}
            </div>
          )}
        </div>
      ),
      minWidth: 250,
      sortingField: 'threat_category',
    },
    {
      id: 'priority',
      header: 'Priority',
      cell: (item) => <PriorityBadge priority={item.priority} />,
      width: 100,
      sortingField: 'priority',
    },
    {
      id: 'affected_components',
      header: 'Affected Assets',
      cell: (item) => {
        const comps = Array.isArray(item.affected_components) ? item.affected_components : [];
        if (comps.length === 0) return '\u2014';
        return (
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {comps.slice(0, 4).map((c, i) => <Badge key={i} color="blue">{c}</Badge>)}
            {comps.length > 4 && <Badge color="grey">+{comps.length - 4}</Badge>}
          </div>
        );
      },
      minWidth: 180,
    },
    {
      id: 'mitigations',
      header: 'Mitigations',
      cell: (item) => {
        const count = item.mitigations.length;
        if (count === 0) return <Box color="text-status-inactive">{'\u2014'}</Box>;
        return (
          <Popover
            position="left"
            size="large"
            triggerType="custom"
            content={
              <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                <MitigationsList mitigations={item.mitigations} />
              </div>
            }
            header={`Mitigations for ${item.threat_id}`}
          >
            <Button variant="inline-link">
              {count} mitigation{count !== 1 ? 's' : ''}
            </Button>
          </Popover>
        );
      },
      minWidth: 150,
    },
    {
      id: 'actions',
      header: 'Action',
      cell: (item) => (
        <Button
          variant="link"
          onClick={() => navigate(`/applications/${appId}/versions/${versionId}/threats/${item.idx}`)}
        >
          See attack tree
        </Button>
      ),
      width: 150,
    },
  ];

  return (
    <CloudscapeShell
      activePage="/applications"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: appName, href: `/applications/${appId}` },
        { text: 'Threat Model', href: `/applications/${appId}/versions/${versionId}` },
      ]}
    >
      {error && <Alert type="error" header="Error loading threat model">{error}</Alert>}
      {loading ? (
        <Box textAlign="center" padding="l"><Spinner size="large" /></Box>
      ) : data ? (
        <SpaceBetween size="m">
          <Header
            variant="h1"
            actions={
              <ExportButton
                summaryData={data}
                appId={appId}
                versionId={versionId}
              />
            }
          >
            Threat Model Summary
          </Header>
          <SummaryBar data={data} totalMitigations={totalMitigations} />
          <Table
            columnDefinitions={COLUMN_DEFINITIONS}
            items={tableItems}
            header={
              <Header variant="h2" counter={`(${tableItems.length})`}>
                Threat Statements
              </Header>
            }
            empty={
              <Box textAlign="center" color="text-status-inactive" padding="l">
                No threat statements available.
              </Box>
            }
            variant="container"
            wrapLines
            stripedRows
          />
        </SpaceBetween>
      ) : null}
    </CloudscapeShell>
  );
}
