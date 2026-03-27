import { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import Box from '@cloudscape-design/components/box';
import Header from '@cloudscape-design/components/header';
import Alert from '@cloudscape-design/components/alert';
import Spinner from '@cloudscape-design/components/spinner';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Container from '@cloudscape-design/components/container';
import Badge from '@cloudscape-design/components/badge';
import Table from '@cloudscape-design/components/table';
import Button from '@cloudscape-design/components/button';
import Link from '@cloudscape-design/components/link';
import Popover from '@cloudscape-design/components/popover';
import Tabs from '@cloudscape-design/components/tabs';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Select from '@cloudscape-design/components/select';
import FormField from '@cloudscape-design/components/form-field';
import Grid from '@cloudscape-design/components/grid';
import CloudscapeShell from '../components/CloudscapeShell';
import ExportButton from '../components/ExportButton';
import { aggregateMitigations } from '../utils/mitigation-aggregator';
import { renderFormattedText } from '../utils/text-formatter';

const PRIORITY_COLORS = { 1: 'red', 2: 'red', 3: 'blue', high: 'red', critical: 'red', medium: 'blue', low: 'grey' };

const REMEDIATION_LABELS = {
  quick_win: { label: 'Quick Win', color: 'green' },
  short_term: { label: 'Short Term', color: 'blue' },
  medium_term: { label: 'Medium Term', color: 'blue' },
  long_term: { label: 'Long Term', color: 'grey' },
  monitoring: { label: 'Monitoring', color: 'grey' },
};

function priorityLabel(p) {
  if (typeof p === 'number') return ['', 'Critical', 'High', 'Medium', 'Low'][p] || `P${p}`;
  return p || '\u2014';
}

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
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {mitigations.map((m, i) => {
        const rt = m.remediationType || m.remediation_type;
        const rtInfo = REMEDIATION_LABELS[rt] || null;
        return (
          <div key={i} style={{ padding: '8px 12px', background: '#fafafa', borderRadius: '6px', border: '1px solid #e9ebed' }}>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              {m.priority && <Badge color={PRIORITY_COLORS[m.priority] || 'grey'}>
                {priorityLabel(m.priority)}
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

// ─── Helper: get affected components for a threat ───
function getAffectedComponents(tree, threats) {
  const matchId = (tree.threat_id || '').replace(/ \[AttackTree.*\]/, '');
  const match = threats.find(t => (t.id || t.threat_id) === matchId);
  return match?.affected_components || match?.impactedAssets || [];
}

// ─── Globally-deduplicated mitigations across all trees ───
function aggregateAllMitigations(attackTrees, threats) {
  const map = new Map(); // key = mitigation name

  for (const tree of attackTrees) {
    const threatId = tree.threat_id || '';
    const threatCategory = tree.threat_category || '';
    const affected = getAffectedComponents(tree, threats);
    const mits = aggregateMitigations(tree);

    for (const mit of mits) {
      if (!mit.name) continue;

      if (!map.has(mit.name)) {
        map.set(mit.name, {
          name: mit.name,
          description: mit.description || '',
          remediationType: mit.remediationType || '',
          priority: mit.priority,
          techniqueId: mit.techniqueId || '',
          evidence: mit.evidence || [],
          attackSteps: [...mit.attackSteps],
          threats: [],
          allAffectedAssets: new Set(),
        });
      }

      const entry = map.get(mit.name);

      // Merge fields if missing
      if (!entry.description && mit.description) entry.description = mit.description;
      if (!entry.remediationType && mit.remediationType) entry.remediationType = mit.remediationType;
      if (!entry.priority && mit.priority) entry.priority = mit.priority;
      if (!entry.techniqueId && mit.techniqueId) entry.techniqueId = mit.techniqueId;
      if (entry.evidence.length === 0 && mit.evidence?.length > 0) entry.evidence = mit.evidence;

      // Track related threats
      if (threatId && !entry.threats.some(t => t.id === threatId)) {
        entry.threats.push({ id: threatId, category: threatCategory });
      }

      // Track affected assets
      for (const a of affected) entry.allAffectedAssets.add(a);
    }
  }

  // Convert Sets to arrays
  return [...map.values()].map(entry => ({
    ...entry,
    affectedAssets: [...entry.allAffectedAssets],
    allAffectedAssets: undefined,
  }));
}

// ─── Mitigations Tab Content ───
function MitigationsTab({ attackTrees, threats }) {
  const allMitigations = useMemo(
    () => aggregateAllMitigations(attackTrees, threats),
    [attackTrees, threats]
  );

  // Filter state
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [selectedRemediation, setSelectedRemediation] = useState(null);
  const [selectedPriority, setSelectedPriority] = useState(null);

  const threatOptions = useMemo(() => {
    const ids = new Set();
    for (const m of allMitigations) {
      for (const t of m.threats) ids.add(t.id);
    }
    return [...ids].sort().map(id => ({ label: id, value: id }));
  }, [allMitigations]);

  const remediationOptions = useMemo(() => {
    const types = [...new Set(allMitigations.map(m => m.remediationType))].filter(Boolean).sort();
    return types.map(rt => ({
      label: REMEDIATION_LABELS[rt]?.label || rt,
      value: rt,
    }));
  }, [allMitigations]);

  const priorityOptions = useMemo(() => {
    const pris = [...new Set(allMitigations.map(m => m.priority))].filter(Boolean).sort();
    return pris.map(p => ({ label: priorityLabel(p), value: String(p) }));
  }, [allMitigations]);

  const filteredMitigations = useMemo(() => {
    let items = allMitigations;
    if (selectedThreat) {
      items = items.filter(m => m.threats.some(t => t.id === selectedThreat.value));
    }
    if (selectedRemediation) {
      items = items.filter(m => m.remediationType === selectedRemediation.value);
    }
    if (selectedPriority) {
      items = items.filter(m => String(m.priority) === selectedPriority.value);
    }
    return items;
  }, [allMitigations, selectedThreat, selectedRemediation, selectedPriority]);

  // Sorting
  const [sortingColumn, setSortingColumn] = useState(null);
  const [sortingDescending, setSortingDescending] = useState(false);

  const REMEDIATION_ORDER = { quick_win: 0, short_term: 1, medium_term: 2, long_term: 3, monitoring: 4 };

  const sortedMitigations = useMemo(() => {
    if (!sortingColumn?.sortingField) return filteredMitigations;
    const field = sortingColumn.sortingField;
    const sorted = [...filteredMitigations].sort((a, b) => {
      const aVal = a[field] ?? '';
      const bVal = b[field] ?? '';
      if (field === 'remediationType') {
        return (REMEDIATION_ORDER[aVal] ?? 99) - (REMEDIATION_ORDER[bVal] ?? 99);
      }
      if (field === 'priority') {
        const pa = typeof aVal === 'number' ? aVal : 99;
        const pb = typeof bVal === 'number' ? bVal : 99;
        return pa - pb;
      }
      if (typeof aVal === 'number' && typeof bVal === 'number') return aVal - bVal;
      return String(aVal).localeCompare(String(bVal));
    });
    return sortingDescending ? sorted.reverse() : sorted;
  }, [filteredMitigations, sortingColumn, sortingDescending]);

  const isFiltered = selectedThreat || selectedRemediation || selectedPriority;
  const counterText = isFiltered
    ? `(${filteredMitigations.length} of ${allMitigations.length})`
    : `(${allMitigations.length})`;

  const MITIGATION_COLUMNS = [
    {
      id: 'priority',
      header: 'Priority',
      cell: (item) => {
        const p = item.priority;
        return <Badge color={PRIORITY_COLORS[p] || PRIORITY_COLORS[String(p).toLowerCase()] || 'grey'}>{priorityLabel(p)}</Badge>;
      },
      sortingField: 'priority',
      width: 90,
    },
    {
      id: 'name',
      header: 'Mitigation',
      cell: (item) => (
        <div style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>
          <div>{item.name}</div>
          {item.description && (
            <ExpandableSection headerText="Implementation guidance" variant="footer">
              <div style={{ lineHeight: '1.6', color: '#414d5c' }}>
                {renderFormattedText(item.description)}
              </div>
            </ExpandableSection>
          )}
        </div>
      ),
      sortingField: 'name',
      minWidth: 250,
    },
    {
      id: 'remediationType',
      header: 'Type',
      cell: (item) => {
        const rt = item.remediationType;
        if (!rt) return '\u2014';
        const info = REMEDIATION_LABELS[rt] || { label: rt, color: 'grey' };
        return <Badge color={info.color}>{info.label}</Badge>;
      },
      sortingField: 'remediationType',
      width: 110,
    },
    {
      id: 'threats',
      header: 'Related Threats',
      cell: (item) => {
        if (!item.threats || item.threats.length === 0) return '\u2014';
        return (
          <div style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>
            {item.threats.map((t, i) => (
              <div key={i} style={{ marginBottom: i < item.threats.length - 1 ? '4px' : 0 }}>
                <span style={{ fontWeight: 500 }}>{t.id}</span>
                {t.category && <span style={{ fontSize: '12px', color: '#5f6b7a' }}> — {t.category}</span>}
              </div>
            ))}
          </div>
        );
      },
      sortingField: 'threatCount',
      minWidth: 180,
    },
    {
      id: 'affectedAssets',
      header: 'Affected Assets',
      cell: (item) => {
        const comps = Array.isArray(item.affectedAssets) ? item.affectedAssets : [];
        if (comps.length === 0) return '\u2014';
        return (
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {comps.slice(0, 3).map((c, i) => <Badge key={i} color="blue">{c}</Badge>)}
            {comps.length > 3 && <Badge color="grey">+{comps.length - 3}</Badge>}
          </div>
        );
      },
      minWidth: 150,
    },
    {
      id: 'technique',
      header: 'Technique',
      cell: (item) => {
        if (!item.techniqueId) return '\u2014';
        let url;
        if (item.techniqueId.startsWith('AML.')) {
          url = `https://atlas.mitre.org/techniques/${item.techniqueId}`;
        } else {
          url = `https://attack.mitre.org/techniques/${item.techniqueId.replace('.', '/')}/`;
        }
        return <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: '#0972d3' }}>{item.techniqueId}</a>;
      },
      width: 130,
    },
    {
      id: 'evidence',
      header: 'Evidence',
      cell: (item) => {
        if (!item.evidence || item.evidence.length === 0) return '\u2014';
        return (
          <ExpandableSection headerText={`${item.evidence.length} source${item.evidence.length > 1 ? 's' : ''}`} variant="footer">
            <div style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>
              {item.evidence.map((e, i) => (
                <div key={i} style={{ marginBottom: '4px', fontSize: '12px' }}>
                  <Badge color="grey">{e.source_type}</Badge>{' '}
                  <span style={{ color: '#5f6b7a' }}>{e.source_ref}</span>
                  {e.relevance && <div style={{ color: '#687078', fontStyle: 'italic' }}>{e.relevance}</div>}
                </div>
              ))}
            </div>
          </ExpandableSection>
        );
      },
      minWidth: 150,
    },
  ];

  return (
    <SpaceBetween size="m">
      {/* Filter Bar */}
      <Grid gridDefinition={[{ colspan: 3 }, { colspan: 3 }, { colspan: 3 }, { colspan: 3 }]}>
        <FormField label="Filter by threat">
          <Select
            selectedOption={selectedThreat}
            onChange={({ detail }) => setSelectedThreat(detail.selectedOption)}
            options={threatOptions}
            placeholder="All threats"
          />
        </FormField>
        <FormField label="Filter by remediation type">
          <Select
            selectedOption={selectedRemediation}
            onChange={({ detail }) => setSelectedRemediation(detail.selectedOption)}
            options={remediationOptions}
            placeholder="All types"
          />
        </FormField>
        <FormField label="Filter by priority">
          <Select
            selectedOption={selectedPriority}
            onChange={({ detail }) => setSelectedPriority(detail.selectedOption)}
            options={priorityOptions}
            placeholder="All priorities"
          />
        </FormField>
        <Box padding={{ top: 'l' }}>
          <Button
            variant="link"
            onClick={() => { setSelectedThreat(null); setSelectedRemediation(null); setSelectedPriority(null); }}
            disabled={!isFiltered}
          >
            Clear filters
          </Button>
        </Box>
      </Grid>

      {/* Mitigations Table */}
      <Table
        columnDefinitions={MITIGATION_COLUMNS}
        items={sortedMitigations}
        sortingColumn={sortingColumn}
        sortingDescending={sortingDescending}
        onSortingChange={({ detail }) => {
          setSortingColumn(detail.sortingColumn);
          setSortingDescending(detail.isDescending);
        }}
        resizableColumns
        header={
          <Header variant="h2" counter={counterText}>
            All Mitigations
          </Header>
        }
        empty={
          <Box textAlign="center" color="text-status-inactive" padding="l">
            No mitigations available
          </Box>
        }
        variant="container"
        wrapLines
        stripedRows
      />
    </SpaceBetween>
  );
}

// ─── Overview Tab Content ───
function OverviewTab({ tableItems, navigate, appId, versionId }) {
  const COLUMN_DEFINITIONS = [
    {
      id: 'threat_id',
      header: 'ID',
      cell: (item) => (
        <Link
          href={`/applications/${appId}/versions/${versionId}/threats/${item.idx}`}
          onFollow={(e) => { e.preventDefault(); navigate(`/applications/${appId}/versions/${versionId}/threats/${item.idx}`); }}
          fontWeight="bold"
        >
          {item.threat_id}
        </Link>
      ),
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
  );
}

// ─── Main Page ───
export default function ThreatModelSummaryPage() {
  const { appId, versionId } = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [appName, setAppName] = useState(appId);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const activeTab = searchParams.get('tab') || 'overview';

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
  const threats = data?.threats || [];

  const tableItems = useMemo(() => {
    return attackTrees.map((tree, idx) => ({
      idx,
      threat_id: tree.threat_id || `Threat ${idx + 1}`,
      threat_category: tree.threat_category || 'Unknown',
      priority: tree.priority || '\u2014',
      threat_statement: tree.threat_statement || tree.threat_description || '',
      threatSource: tree.threatSource || '',
      affected_components: getAffectedComponents(tree, threats),
      mitigations: aggregateMitigations(tree),
      mapping_count: tree.mapping_count || (tree.ttc_mappings || []).length,
      step_count: (tree.attack_steps || []).length,
    }));
  }, [attackTrees, threats]);

  // Globally-deduplicated mitigation count (consistent with mitigations tab)
  const globalMitigations = useMemo(
    () => aggregateAllMitigations(attackTrees, threats),
    [attackTrees, threats]
  );

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
          <SummaryBar data={data} totalMitigations={globalMitigations.length} />
          <Tabs
            activeTabId={activeTab}
            onChange={({ detail }) => setSearchParams({ tab: detail.activeTabId })}
            tabs={[
              {
                id: 'overview',
                label: 'Overview',
                content: (
                  <OverviewTab
                    tableItems={tableItems}
                    navigate={navigate}
                    appId={appId}
                    versionId={versionId}
                  />
                ),
              },
              {
                id: 'mitigations',
                label: `Mitigations (${globalMitigations.length})`,
                content: (
                  <MitigationsTab
                    attackTrees={attackTrees}
                    threats={threats}
                  />
                ),
              },
            ]}
          />
        </SpaceBetween>
      ) : null}
    </CloudscapeShell>
  );
}
