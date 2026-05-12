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
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import Select from '@cloudscape-design/components/select';
import FormField from '@cloudscape-design/components/form-field';
import Grid from '@cloudscape-design/components/grid';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import CloudscapeShell from '../components/CloudscapeShell';
import ExportButton from '../components/ExportButton';
import { aggregateMitigations } from '../utils/mitigation-aggregator';
import { renderFormattedText } from '../utils/text-formatter';
import { mitigationToMarkdown } from '../utils/mitigation-markdown';
import { getApplication, getApplicationVersions, getFrameworks } from '../api-client';
import { buildTechniqueUrl } from '../utils/technique-url';

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

/**
 * Render the interviewer summary string, which may contain `## Section` markers
 * produced by the threat-review stage. Splits the text on those markers and
 * renders each section with its own subheading.
 */
function InterviewerSummarySections({ text }) {
  if (!text) return null;
  const trimmed = String(text).trim();
  if (!trimmed.startsWith('## ')) {
    // Legacy / unstructured — render verbatim.
    return <Box variant="p">{trimmed}</Box>;
  }
  // Split on '## ' markers. First element is empty because the string starts with '## '.
  const parts = trimmed.split(/^##\s+/m).filter((p) => p.trim().length > 0);
  return (
    <SpaceBetween size="m">
      {parts.map((part, i) => {
        const firstNewline = part.indexOf('\n');
        const heading = firstNewline === -1 ? part.trim() : part.slice(0, firstNewline).trim();
        const body = firstNewline === -1 ? '' : part.slice(firstNewline + 1).trim();
        return (
          <div key={i}>
            <Box variant="h4" margin={{ bottom: 'xxs' }}>{heading}</Box>
            {body.split('\n').map((line, li) => (
              <Box key={li} variant="p">{line}</Box>
            ))}
          </div>
        );
      })}
    </SpaceBetween>
  );
}

function formatDuration(seconds) {
  if (seconds == null) return '—';
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.round(seconds - minutes * 60);
  if (minutes < 60) return remaining ? `${minutes} m ${remaining} s` : `${minutes} m`;
  const hours = Math.floor(minutes / 60);
  const restMin = minutes - hours * 60;
  return restMin ? `${hours} h ${restMin} m` : `${hours} h`;
}

function formatStartedAt(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  } catch {
    return iso;
  }
}

/**
 * Map a Bedrock / Anthropic model ID to a human-friendly label.
 *
 *   global.anthropic.claude-opus-4-7   → Claude Opus 4.7
 *   anthropic.claude-sonnet-4-6-...    → Claude Sonnet 4.6
 *   us.anthropic.claude-haiku-4-5      → Claude Haiku 4.5
 *
 * Falls back to the raw id when the pattern doesn't match.
 */
function friendlyModelName(id) {
  if (!id) return '';
  const match = id.match(/claude-(opus|sonnet|haiku)-(\d+)-(\d+)/i);
  if (!match) return id;
  const family = match[1].charAt(0).toUpperCase() + match[1].slice(1).toLowerCase();
  return `Claude ${family} ${match[2]}.${match[3]}`;
}

/**
 * One-time onboarding banner that explains how to read the report. Shown
 * until the user dismisses it; the dismissal is stored in localStorage under
 * a single global key so returning users don't keep seeing it.
 *
 * The key is intentionally global (not per-app or per-version) because the
 * banner teaches how to use the tool, not how to interpret a specific run.
 */
const ONBOARDING_DISMISS_KEY = 'tf-summary-onboarding-dismissed-v1';

function OnboardingBanner() {
  const [dismissed, setDismissed] = useState(() => {
    try {
      return localStorage.getItem(ONBOARDING_DISMISS_KEY) === '1';
    } catch {
      return false;
    }
  });

  if (dismissed) return null;

  const handleDismiss = () => {
    try { localStorage.setItem(ONBOARDING_DISMISS_KEY, '1'); } catch { /* ignore */ }
    setDismissed(true);
  };

  return (
    <Alert
      type="info"
      header="Where do I start?"
      dismissible
      onDismiss={handleDismiss}
    >
      <SpaceBetween size="xxs">
        <Box variant="p">
          <strong>Developers:</strong> jump to the <em>Mitigations</em> tab, filter by <em>Quick Win</em>, and use the <em>Copy as Markdown</em> buttons to drop guidance into your tickets.
        </Box>
        <Box variant="p">
          <strong>Security reviewers:</strong> open the <em>Threats</em> tab to triage by priority, then click into a threat to inspect the attack tree, mapped MITRE ATT&amp;CK techniques, and recommended controls.
        </Box>
      </SpaceBetween>
    </Alert>
  );
}

function buildRunMetaParts(meta, frameworkCatalog) {
  const keys = meta?.frameworks || [];
  const frameworkNames = keys.length
    ? keys.map((k) => frameworkCatalog?.[k]?.name || k)
    : [];
  let frameworksLabel;
  if (frameworkNames.length === 0) {
    frameworksLabel = 'all frameworks';
  } else if (frameworkNames.length <= 2) {
    frameworksLabel = frameworkNames.join(', ');
  } else {
    frameworksLabel = `${frameworkNames[0]} + ${frameworkNames.length - 1} more`;
  }
  return {
    model: friendlyModelName(meta?.model_id),
    started: formatStartedAt(meta?.started_at),
    duration: meta?.duration_seconds != null ? formatDuration(meta.duration_seconds) : null,
    frameworks: frameworksLabel,
    frameworkNames,
  };
}

function RunMetaBar({ meta, frameworkCatalog }) {
  if (!meta) return null;
  const p = buildRunMetaParts(meta, frameworkCatalog);
  return (
    <ExpandableSection
      variant="container"
      headerText="Run metadata"
    >
      <ColumnLayout columns={4} variant="text-grid">
        <div>
          <Box variant="awsui-key-label">Model</Box>
          <div>{p.model || '—'}</div>
        </div>
        <div>
          <Box variant="awsui-key-label">Started</Box>
          <div>{p.started}</div>
        </div>
        <div>
          <Box variant="awsui-key-label">Duration</Box>
          <div>{p.duration ?? '—'}</div>
        </div>
        <div>
          <Box variant="awsui-key-label">Frameworks</Box>
          <div>
            {p.frameworkNames.length ? p.frameworkNames.join(', ') : 'all frameworks'}
          </div>
        </div>
      </ColumnLayout>
    </ExpandableSection>
  );
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
      <ColumnLayout columns={stats.length} variant="text-grid">
        {stats.map((s, i) => (
          <Box key={i} textAlign="center">
            <Box variant="awsui-key-label">{s.label}</Box>
            <Box
              fontSize="display-l"
              fontWeight="bold"
              color={s.color ? 'text-status-error' : 'inherit'}
            >
              {s.value}
            </Box>
          </Box>
        ))}
      </ColumnLayout>
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
            <SpaceBetween size="xs">
              <ExpandableSection headerText="Implementation guidance" variant="footer">
                <div style={{ lineHeight: '1.6', color: '#414d5c' }}>
                  {renderFormattedText(item.description)}
                </div>
              </ExpandableSection>
              <CopyToClipboard
                variant="button"
                copyButtonText="Copy as Markdown"
                textToCopy={mitigationToMarkdown(item)}
                copyButtonAriaLabel={`Copy ${item.name} as Markdown`}
                copySuccessText="Copied to clipboard"
                copyErrorText="Failed to copy"
              />
            </SpaceBetween>
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
      header: 'Mapped TTP',
      cell: (item) => {
        if (!item.techniqueId) return '\u2014';
        const url = buildTechniqueUrl(item.techniqueId);
        if (!url) return item.techniqueId;
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

// ─── Section helper ───
function Section({ title, children, defaultExpanded = true }) {
  return (
    <Container header={<Header variant="h3">{title}</Header>}>
      {children}
    </Container>
  );
}

function KeyValue({ label, children }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <div>{children || '\u2014'}</div>
    </div>
  );
}

function BadgeList({ items, color = 'blue' }) {
  if (!items || items.length === 0) return <Box color="text-status-inactive">{'\u2014'}</Box>;
  return (
    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
      {items.map((item, i) => <Badge key={i} color={color}>{item}</Badge>)}
    </div>
  );
}

function BulletList({ items }) {
  if (!items || items.length === 0) return <Box color="text-status-inactive">{'\u2014'}</Box>;
  return (
    <ul style={{ margin: 0, paddingLeft: '20px' }}>
      {items.map((item, i) => (
        <li key={i} style={{ marginBottom: '6px', lineHeight: '1.5' }}>{item}</li>
      ))}
    </ul>
  );
}

// ─── Application Overview Tab ───
function ApplicationOverviewTab({ scannerContext, projectInfo }) {
  const ctx = scannerContext || {};
  const info = projectInfo || {};
  const userCtx = ctx.user_context || {};
  const secControls = ctx.security_controls || {};

  const deploymentType = userCtx.deployment_state
    || userCtx.environment_type
    || (ctx.cloud_provider ? `${ctx.cloud_provider.toUpperCase()} deployment` : null)
    || info.deployment_environment
    || null;

  const industry = userCtx.industry || ctx.industry || info.industry || null;

  return (
    <SpaceBetween size="l">
      {/* Description */}
      {(info.short_summary || ctx.description) && (
        <Container header={<Header variant="h3">Description</Header>}>
          <Box variant="p">{info.short_summary || ctx.description}</Box>
        </Container>
      )}

      {/* Key attributes row */}
      <Container header={<Header variant="h3">Application Details</Header>}>
        <ColumnLayout columns={3} variant="text-grid">
          <KeyValue label="Industry">{industry}</KeyValue>
          <KeyValue label="Deployment type">{deploymentType}</KeyValue>
          <KeyValue label="Cloud provider">{ctx.cloud_provider ? ctx.cloud_provider.toUpperCase() : null}</KeyValue>
        </ColumnLayout>
      </Container>

      {/* Components found */}
      <Section title="Components found">
        <BadgeList items={ctx.services} />
      </Section>

      {/* Files scanned */}
      <Section title="Files scanned">
        {ctx.files_analyzed && ctx.files_analyzed.length > 0 ? (
          <SpaceBetween size="xs">
            <BadgeList items={ctx.files_analyzed} color="grey" />
            {ctx.files_skipped_reason && ctx.files_skipped_reason.length > 0 && (
              <ExpandableSection headerText={`${ctx.files_skipped_reason.length} file${ctx.files_skipped_reason.length !== 1 ? 's' : ''} or director${ctx.files_skipped_reason.length !== 1 ? 'ies' : 'y'} skipped`} variant="footer">
                <BulletList items={ctx.files_skipped_reason} />
              </ExpandableSection>
            )}
          </SpaceBetween>
        ) : (
          <Box color="text-status-inactive">{'\u2014'}</Box>
        )}
      </Section>

      {/* Authentication mechanisms */}
      <Section title="Authentication mechanisms found">
        <BulletList items={ctx.auth_mechanisms} />
      </Section>

      {/* Main risks inferred */}
      <Section title="Main risks inferred">
        <BulletList items={ctx.critical_findings} />
      </Section>

      {/* User-provided context (from interview agent) */}
      {Object.keys(userCtx).length > 0 && (
        <Section title="Additional context (interview)">
          <SpaceBetween size="m">
            <ColumnLayout columns={2} variant="text-grid">
              {userCtx.data_sensitivity && (
                <KeyValue label="Data sensitivity">{userCtx.data_sensitivity}</KeyValue>
              )}
              {userCtx.primary_threat_concern && (
                <KeyValue label="Primary threat concern">{userCtx.primary_threat_concern}</KeyValue>
              )}
              {userCtx.compliance_requirements && (
                <KeyValue label="Compliance requirements">{userCtx.compliance_requirements}</KeyValue>
              )}
              {userCtx.studio_credential_model && (
                <KeyValue label="Credential model">{userCtx.studio_credential_model}</KeyValue>
              )}
            </ColumnLayout>
            {userCtx.threat_model_focus && userCtx.threat_model_focus.length > 0 && (
              <div>
                <Box variant="awsui-key-label">Threat model focus areas</Box>
                <BulletList items={userCtx.threat_model_focus} />
              </div>
            )}
            {userCtx.existing_controls_status && (
              <ExpandableSection headerText="Existing controls status" variant="footer">
                <ColumnLayout columns={2} variant="text-grid">
                  {Object.entries(userCtx.existing_controls_status).map(([key, val]) => (
                    <KeyValue key={key} label={key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}>
                      {val}
                    </KeyValue>
                  ))}
                </ColumnLayout>
              </ExpandableSection>
            )}
          </SpaceBetween>
        </Section>
      )}

      {/* Interviewer summary */}
      {ctx.interviewer_summary && (
        <Container header={<Header variant="h3">Interviewer summary</Header>}>
          <InterviewerSummarySections text={ctx.interviewer_summary} />
          {ctx.interviewer_confidence && (
            <Box variant="small" color="text-body-secondary" margin={{ top: 'xs' }}>
              Confidence: <Badge color={ctx.interviewer_confidence === 'high' ? 'green' : ctx.interviewer_confidence === 'medium' ? 'blue' : 'grey'}>{ctx.interviewer_confidence}</Badge>
            </Box>
          )}
        </Container>
      )}

      {/* Security controls */}
      {Object.keys(secControls).length > 0 && (
        <Section title="Security controls observed">
          <ColumnLayout columns={2} variant="text-grid">
            {Object.entries(secControls).map(([key, val]) => (
              <KeyValue key={key} label={key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}>
                {val}
              </KeyValue>
            ))}
          </ColumnLayout>
        </Section>
      )}

      {/* Data flows */}
      {ctx.data_flows && ctx.data_flows.length > 0 && (
        <Section title="Data flows">
          <BulletList items={ctx.data_flows} />
        </Section>
      )}

      {/* Trust boundaries */}
      {ctx.trust_boundaries && ctx.trust_boundaries.length > 0 && (
        <Section title="Trust boundaries">
          <BulletList items={ctx.trust_boundaries} />
        </Section>
      )}
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
  // True once we've confirmed a persistent app record owns this appId — at
  // that point we stop trusting project_info.application_name from the run
  // data, which can be a stale folder basename.
  const [persistentAppLoaded, setPersistentAppLoaded] = useState(false);
  const [versionLabel, setVersionLabel] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [frameworkCatalog, setFrameworkCatalog] = useState({});

  const activeTab = searchParams.get('tab') || 'application';

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
        // Only use the run-data app name for legacy folder-derived apps
        // that have no persistent record.
        if (!persistentAppLoaded) {
          if (json.project_info?.application_name) setAppName(json.project_info.application_name);
          else if (json.application_name) setAppName(json.application_name);
        }
      } catch (err) {
        if (!cancelled) setError(err.message || 'Failed to load');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchVersion();
    return () => { cancelled = true; };
  }, [appId, versionId, persistentAppLoaded]);

  // Load the framework catalog once so we can render run_metadata.frameworks
  // with friendly names (e.g. "MITRE ATT&CK Enterprise") instead of keys.
  useEffect(() => {
    let cancelled = false;
    getFrameworks()
      .then((d) => { if (!cancelled && d?.frameworks) setFrameworkCatalog(d.frameworks); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  // Authoritative app name from the persistent record. Wins over any name
  // embedded in run-data. If the record is missing (legacy folder-derived
  // app), silently fall back to whatever fetchVersion populated.
  useEffect(() => {
    let cancelled = false;
    getApplication(appId)
      .then((app) => {
        if (cancelled || !app?.name) return;
        setAppName(app.name);
        setPersistentAppLoaded(true);
      })
      .catch(() => { /* keep legacy fallback */ });
    return () => { cancelled = true; };
  }, [appId]);

  // Resolve a friendly label for the current version ("Latest" when the URL
  // param is literal "latest"; otherwise "Version N" pulled from the list).
  useEffect(() => {
    let cancelled = false;
    if (versionId === 'latest') {
      setVersionLabel('Latest');
      return () => { cancelled = true; };
    }
    getApplicationVersions(appId)
      .then(({ versions = [] }) => {
        if (cancelled) return;
        const match = versions.find((v) => v.id === versionId);
        setVersionLabel(match?.display_name || versionId);
      })
      .catch(() => { if (!cancelled) setVersionLabel(versionId); });
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
        {
          text: versionLabel || 'Latest threat model',
          href: `/applications/${appId}/versions/${versionId}`,
        },
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
          <OnboardingBanner />
          <SummaryBar data={data} totalMitigations={globalMitigations.length} />
          <Tabs
            activeTabId={activeTab}
            onChange={({ detail }) => setSearchParams({ tab: detail.activeTabId })}
            tabs={[
              {
                id: 'application',
                label: 'Application',
                content: (
                  <ApplicationOverviewTab
                    scannerContext={data?.scanner_context}
                    projectInfo={data?.project_info}
                  />
                ),
              },
              {
                id: 'overview',
                label: 'Threats',
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
          <RunMetaBar meta={data?.run_metadata} frameworkCatalog={frameworkCatalog} />
        </SpaceBetween>
      ) : null}
    </CloudscapeShell>
  );
}
