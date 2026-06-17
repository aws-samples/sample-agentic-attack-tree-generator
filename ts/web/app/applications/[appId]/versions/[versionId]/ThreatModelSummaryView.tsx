'use client';

/**
 * ThreatModelSummaryView — TS/Next port of console-ui's ThreatModelSummaryPage.jsx.
 *
 * Three-tab dashboard for a finished threat model version:
 *   - Application: scanner context + interview-derived context
 *   - Threats: the threat-statement table (deep-links into the per-threat view)
 *   - Mitigations: globally-deduplicated mitigations with the editable status layer
 *
 * react-router (useParams/useNavigate/useSearchParams) → next/navigation
 * (useParams/useRouter/useSearchParams). CloudscapeShell → AppShell.
 */

import { useState, useEffect, useMemo, type ReactNode } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useRealParams } from '@/hooks/useRealParams';
import Box from '@cloudscape-design/components/box';
import Header from '@cloudscape-design/components/header';
import Alert from '@cloudscape-design/components/alert';
import Spinner from '@cloudscape-design/components/spinner';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Container from '@cloudscape-design/components/container';
import Badge, { type BadgeProps } from '@cloudscape-design/components/badge';
import Table, { type TableProps } from '@cloudscape-design/components/table';
import Button from '@cloudscape-design/components/button';
import Link from '@cloudscape-design/components/link';
import Popover from '@cloudscape-design/components/popover';
import Tabs from '@cloudscape-design/components/tabs';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import FormField from '@cloudscape-design/components/form-field';
import Grid from '@cloudscape-design/components/grid';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import AppShell from '@/components/AppShell';
import ExportButton from '@/components/ExportButton';
import type { ThreatModelSummary } from '@/utils/export-service';
import MitigationStatusEditor from '@/components/MitigationStatusEditor';
import {
  aggregateMitigations,
  aggregateAllMitigations,
  getAffectedComponentsForTree as getAffectedComponents,
  type AggregatedMitigation,
  type GlobalAggregatedMitigation,
  type ReportAttackTree,
  type ThreatRow,
} from '@/utils/mitigation-aggregator';
import { renderFormattedText } from '@/utils/text-formatter';
import { mitigationToMarkdown } from '@/utils/mitigation-markdown';
import {
  getApplication,
  getApplicationVersions,
  getFrameworks,
  getMitigationOverrides,
} from '@/api/client';
import { buildTechniqueUrl } from '@/utils/technique-url';
import {
  MITIGATION_STATUSES,
  isTerminal as isTerminalStatus,
} from '@/utils/mitigation-status';
import type { MitigationOverride } from '@threatforest/types';

const PRIORITY_COLORS: Record<string, BadgeProps['color']> = {
  '1': 'red',
  '2': 'red',
  '3': 'blue',
  high: 'red',
  critical: 'red',
  medium: 'blue',
  low: 'grey',
};

const REMEDIATION_LABELS: Record<string, { label: string; color: BadgeProps['color'] }> = {
  quick_win: { label: 'Quick Win', color: 'green' },
  short_term: { label: 'Short Term', color: 'blue' },
  medium_term: { label: 'Medium Term', color: 'blue' },
  long_term: { label: 'Long Term', color: 'grey' },
  monitoring: { label: 'Monitoring', color: 'grey' },
};

function priorityLabel(p: number | string | null | undefined): string {
  if (typeof p === 'number') return ['', 'Critical', 'High', 'Medium', 'Low'][p] || `P${p}`;
  return p || '—';
}

function PriorityBadge({ priority }: { priority?: string | null }) {
  const p = (priority || '').toLowerCase();
  const colorMap: Record<string, BadgeProps['color']> = {
    high: 'red',
    critical: 'red',
    medium: 'blue',
    low: 'green',
  };
  return <Badge color={colorMap[p] || 'grey'}>{priority || '—'}</Badge>;
}

/**
 * Render the interviewer summary string, which may contain `## Section` markers
 * produced by the threat-review stage. Splits the text on those markers and
 * renders each section with its own subheading.
 */
function InterviewerSummarySections({ text }: { text?: string | null }) {
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

function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return '—';
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.round(seconds - minutes * 60);
  if (minutes < 60) return remaining ? `${minutes} m ${remaining} s` : `${minutes} m`;
  const hours = Math.floor(minutes / 60);
  const restMin = minutes - hours * 60;
  return restMin ? `${hours} h ${restMin} m` : `${hours} h`;
}

function formatStartedAt(iso: string | null | undefined): string {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const pad = (n: number) => String(n).padStart(2, '0');
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
function friendlyModelName(id: string | null | undefined): string {
  if (!id) return '';
  const match = id.match(/claude-(opus|sonnet|haiku)-(\d+)-(\d+)/i);
  if (!match) return id;
  const family = match[1]!.charAt(0).toUpperCase() + match[1]!.slice(1).toLowerCase();
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
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(ONBOARDING_DISMISS_KEY) === '1';
    } catch {
      return false;
    }
  });

  if (dismissed) return null;

  const handleDismiss = () => {
    try {
      localStorage.setItem(ONBOARDING_DISMISS_KEY, '1');
    } catch {
      /* ignore */
    }
    setDismissed(true);
  };

  return (
    <Alert type="info" header="Where do I start?" dismissible onDismiss={handleDismiss}>
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

interface RunMetadata {
  model_id?: string;
  started_at?: string;
  duration_seconds?: number | null;
  frameworks?: string[];
  [key: string]: unknown;
}

type FrameworkCatalog = Record<string, { name: string; description: string }>;

function RunMetaBar({
  meta,
  frameworkCatalog,
}: {
  meta?: RunMetadata | null;
  frameworkCatalog: FrameworkCatalog;
}) {
  if (!meta) return null;
  const keys = meta.frameworks || [];
  const frameworkNames = keys.length ? keys.map((k) => frameworkCatalog?.[k]?.name || k) : [];
  const model = friendlyModelName(meta.model_id);
  const started = formatStartedAt(meta.started_at);
  const duration = meta.duration_seconds != null ? formatDuration(meta.duration_seconds) : null;
  return (
    <ExpandableSection variant="container" headerText="Run metadata">
      <ColumnLayout columns={4} variant="text-grid">
        <div>
          <Box variant="awsui-key-label">Model</Box>
          <div>{model || '—'}</div>
        </div>
        <div>
          <Box variant="awsui-key-label">Started</Box>
          <div>{started}</div>
        </div>
        <div>
          <Box variant="awsui-key-label">Duration</Box>
          <div>{duration ?? '—'}</div>
        </div>
        <div>
          <Box variant="awsui-key-label">Frameworks</Box>
          <div>{frameworkNames.length ? frameworkNames.join(', ') : 'all frameworks'}</div>
        </div>
      </ColumnLayout>
    </ExpandableSection>
  );
}

/** The loose merged /data report-bundle shape this page consumes. */
interface SummaryData {
  attack_trees?: ReportAttackTree[];
  threats?: ThreatRow[];
  extraction_summary?: { total_threats?: number; high_severity_count?: number };
  mapping_summary?: { total_mappings?: number };
  scanner_context?: ScannerContext | null;
  project_info?: ProjectInfo | null;
  run_metadata?: RunMetadata | null;
  application_name?: string;
  [key: string]: unknown;
}

function SummaryBar({ data, totalMitigations }: { data?: SummaryData | null; totalMitigations: number }) {
  const ext = data?.extraction_summary || {};
  const map = data?.mapping_summary || {};
  const stats: Array<{ label: string; value: number; color?: string }> = [
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
            <Box fontSize="display-l" fontWeight="bold" color={s.color ? 'text-status-error' : 'inherit'}>
              {s.value}
            </Box>
          </Box>
        ))}
      </ColumnLayout>
    </Container>
  );
}

function MitigationsList({ mitigations }: { mitigations: AggregatedMitigation[] }) {
  if (!mitigations || mitigations.length === 0) {
    return <Box color="text-status-inactive">No mitigations</Box>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {mitigations.map((m, i) => {
        const rt = m.remediationType;
        const rtInfo = rt ? REMEDIATION_LABELS[rt] || null : null;
        return (
          <div key={i} style={{ padding: '8px 12px', background: '#fafafa', borderRadius: '6px', border: '1px solid #e9ebed' }}>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              {m.priority != null && m.priority !== '' && (
                <Badge color={PRIORITY_COLORS[String(m.priority)] || 'grey'}>{priorityLabel(m.priority)}</Badge>
              )}
              {rtInfo && <Badge color={rtInfo.color}>{rtInfo.label}</Badge>}
            </div>
            <div style={{ marginTop: '4px', fontWeight: 500 }}>{m.name}</div>
          </div>
        );
      })}
    </div>
  );
}

type GlobalMitigationColumn = TableProps.ColumnDefinition<GlobalAggregatedMitigation>;

// ─── Mitigations Tab Content ───
//
// `overrides` is owned by the parent page so it survives tab unmount/remount.
// Saved/cleared edits flow back up via the callback props rather than living
// in local state here.
function MitigationsTab({
  attackTrees,
  threats,
  appId,
  versionId,
  overrides,
  onOverrideSaved,
  onOverrideCleared,
}: {
  attackTrees: ReportAttackTree[];
  threats: ThreatRow[];
  appId: string;
  versionId: string;
  overrides: Record<string, MitigationOverride>;
  onOverrideSaved: (name: string, override: MitigationOverride) => void;
  onOverrideCleared: (name: string) => void;
}) {
  const router = useRouter();

  const aggregated = useMemo(
    () => aggregateAllMitigations(attackTrees, threats),
    [attackTrees, threats],
  );

  // Map threat_id → its index in attackTrees so the Related Threats column
  // can deep-link into the per-threat dashboard. The dashboard URL uses the
  // tree index, not the TS-prefixed id.
  const threatIdxById = useMemo(() => {
    const m = new Map<string, number>();
    attackTrees.forEach((tree, idx) => {
      const id = tree.threat_id;
      if (id && !m.has(id)) m.set(id, idx);
    });
    return m;
  }, [attackTrees]);

  // Project the aggregated list with the live override layer applied. The
  // /data response also carries server-side override fields, but we always
  // prefer the page-level `overrides` map because it reflects in-flight edits
  // the data blob hasn't been refetched for.
  const allMitigations = useMemo<GlobalAggregatedMitigation[]>(
    () =>
      aggregated.map((m) => {
        const o = overrides?.[m.name];
        if (o) {
          return {
            ...m,
            overrideStatus: o.status,
            overrideComment: o.comment,
            overrideUpdatedAt: o.updated_at,
          };
        }
        // No override in the lifted state — strip any stale fields from the
        // aggregator so a Clear() is reflected immediately.
        return { ...m, overrideStatus: null, overrideComment: '', overrideUpdatedAt: '' };
      }),
    [aggregated, overrides],
  );

  // Filter state
  const [selectedThreat, setSelectedThreat] = useState<SelectProps.Option | null>(null);
  const [selectedRemediation, setSelectedRemediation] = useState<SelectProps.Option | null>(null);
  const [selectedPriority, setSelectedPriority] = useState<SelectProps.Option | null>(null);
  const [selectedStatus, setSelectedStatus] = useState<SelectProps.Option | null>(null);

  const threatOptions = useMemo<SelectProps.Option[]>(() => {
    const ids = new Set<string>();
    for (const m of allMitigations) {
      for (const t of m.threats) ids.add(t.id);
    }
    return [...ids].sort().map((id) => ({ label: id, value: id }));
  }, [allMitigations]);

  const remediationOptions = useMemo<SelectProps.Option[]>(() => {
    const types = [...new Set(allMitigations.map((m) => m.remediationType))].filter(Boolean).sort();
    return types.map((rt) => ({
      label: REMEDIATION_LABELS[rt]?.label || rt,
      value: rt,
    }));
  }, [allMitigations]);

  const priorityOptions = useMemo<SelectProps.Option[]>(() => {
    const pris = [...new Set(allMitigations.map((m) => m.priority))].filter(
      (p): p is number | string => p != null && p !== '',
    ).sort();
    return pris.map((p) => ({ label: priorityLabel(p), value: String(p) }));
  }, [allMitigations]);

  const filteredMitigations = useMemo(() => {
    let items = allMitigations;
    if (selectedThreat) {
      items = items.filter((m) => m.threats.some((t) => t.id === selectedThreat.value));
    }
    if (selectedRemediation) {
      items = items.filter((m) => m.remediationType === selectedRemediation.value);
    }
    if (selectedPriority) {
      items = items.filter((m) => String(m.priority) === selectedPriority.value);
    }
    if (selectedStatus) {
      // 'open' is the synthetic value for "no status set" — anything else is a
      // direct match against override status.
      const v = selectedStatus.value;
      if (v === 'open') items = items.filter((m) => !m.overrideStatus);
      else items = items.filter((m) => m.overrideStatus === v);
    }
    return items;
  }, [allMitigations, selectedThreat, selectedRemediation, selectedPriority, selectedStatus]);

  // Sorting
  // onSortingChange returns a SortingColumn<T> (the narrower sort projection of
  // a column def), so the state holds that shape rather than the full
  // ColumnDefinition.
  const [sortingColumn, setSortingColumn] =
    useState<TableProps.SortingColumn<GlobalAggregatedMitigation> | null>(null);
  const [sortingDescending, setSortingDescending] = useState(false);

  const REMEDIATION_ORDER: Record<string, number> = {
    quick_win: 0,
    short_term: 1,
    medium_term: 2,
    long_term: 3,
    monitoring: 4,
  };

  const sortedMitigations = useMemo(() => {
    const field = sortingColumn?.sortingField as keyof GlobalAggregatedMitigation | undefined;
    if (!field) return filteredMitigations;
    const sorted = [...filteredMitigations].sort((a, b) => {
      const aVal = a[field] ?? '';
      const bVal = b[field] ?? '';
      if (field === 'remediationType') {
        return (REMEDIATION_ORDER[String(aVal)] ?? 99) - (REMEDIATION_ORDER[String(bVal)] ?? 99);
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

  const isFiltered = Boolean(selectedThreat || selectedRemediation || selectedPriority || selectedStatus);
  const counterText = isFiltered
    ? `(${filteredMitigations.length} of ${allMitigations.length})`
    : `(${allMitigations.length})`;

  const MITIGATION_COLUMNS: GlobalMitigationColumn[] = [
    {
      id: 'priority',
      header: 'Priority',
      cell: (item) => {
        const p = item.priority;
        return (
          <Badge color={PRIORITY_COLORS[String(p)] || PRIORITY_COLORS[String(p).toLowerCase()] || 'grey'}>
            {priorityLabel(p)}
          </Badge>
        );
      },
      sortingField: 'priority',
      width: 90,
    },
    {
      id: 'name',
      header: 'Mitigation',
      cell: (item) => {
        // Dim terminal-status rows so the user's eye lands on Open / In progress
        // mitigations first. Editor column stays full-strength so terminal
        // statuses can be inspected and changed.
        const dim = isTerminalStatus(item.overrideStatus);
        return (
          <div style={{ whiteSpace: 'normal', wordBreak: 'break-word', opacity: dim ? 0.55 : 1 }}>
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
        );
      },
      sortingField: 'name',
      minWidth: 250,
    },
    {
      id: 'status',
      header: 'Status',
      cell: (item) => (
        <MitigationStatusEditor
          mitigationKey={item.name}
          appId={appId}
          versionId={versionId}
          status={item.overrideStatus}
          comment={item.overrideComment}
          onSaved={(override) => onOverrideSaved(item.name, override)}
          onCleared={() => onOverrideCleared(item.name)}
        />
      ),
      width: 240,
    },
    {
      id: 'remediationType',
      header: 'Type',
      cell: (item) => {
        const rt = item.remediationType;
        if (!rt) return '—';
        const info = REMEDIATION_LABELS[rt] || { label: rt, color: 'grey' as BadgeProps['color'] };
        return <Badge color={info.color}>{info.label}</Badge>;
      },
      sortingField: 'remediationType',
      width: 110,
    },
    {
      id: 'threats',
      header: 'Related Threats',
      cell: (item) => {
        if (!item.threats || item.threats.length === 0) return '—';
        return (
          <div style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>
            {item.threats.map((t, i) => {
              const idx = threatIdxById.get(t.id);
              const linkable = idx !== undefined && appId && versionId;
              const href = linkable
                ? `/applications/${appId}/versions/${versionId}/threats/${idx}`
                : null;
              return (
                <div key={i} style={{ marginBottom: i < item.threats.length - 1 ? '4px' : 0 }}>
                  {linkable && href ? (
                    <Link
                      href={href}
                      onFollow={(e) => {
                        e.preventDefault();
                        router.push(href);
                      }}
                    >
                      <Box fontWeight="bold" display="inline">
                        {t.id}
                      </Box>
                    </Link>
                  ) : (
                    <span style={{ fontWeight: 500 }}>{t.id}</span>
                  )}
                  {t.category && <span style={{ fontSize: '12px', color: '#5f6b7a' }}> — {t.category}</span>}
                </div>
              );
            })}
          </div>
        );
      },
      minWidth: 180,
    },
    {
      id: 'affectedAssets',
      header: 'Affected Assets',
      cell: (item) => {
        const comps = Array.isArray(item.affectedAssets) ? item.affectedAssets : [];
        if (comps.length === 0) return '—';
        const overflow = comps.slice(3);
        return (
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {comps.slice(0, 3).map((c, i) => (
              <Badge key={i} color="blue">{c}</Badge>
            ))}
            {overflow.length > 0 && (
              <Popover
                size="small"
                triggerType="custom"
                dismissButton={false}
                header={`${overflow.length} more asset${overflow.length === 1 ? '' : 's'}`}
                content={
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {overflow.map((c, i) => (
                      <Badge key={i} color="blue">{c}</Badge>
                    ))}
                  </div>
                }
              >
                <span style={{ cursor: 'pointer' }}>
                  <Badge color="grey">+{overflow.length}</Badge>
                </span>
              </Popover>
            )}
          </div>
        );
      },
      minWidth: 150,
    },
    {
      id: 'technique',
      header: 'Mapped TTP',
      cell: (item) => {
        if (!item.techniqueId) return '—';
        const url = buildTechniqueUrl(item.techniqueId);
        if (!url) return item.techniqueId;
        return (
          <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: '#0972d3' }}>
            {item.techniqueId}
          </a>
        );
      },
      width: 130,
    },
    {
      id: 'evidence',
      header: 'Evidence',
      cell: (item) => {
        const evidence = (item.evidence || []) as Array<{
          source_type?: string;
          source_ref?: string;
          relevance?: string;
        }>;
        if (evidence.length === 0) return '—';
        return (
          <ExpandableSection
            headerText={`${evidence.length} source${evidence.length > 1 ? 's' : ''}`}
            variant="footer"
          >
            <div style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>
              {evidence.map((e, i) => (
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
      <Grid gridDefinition={[{ colspan: 3 }, { colspan: 3 }, { colspan: 2 }, { colspan: 2 }, { colspan: 2 }]}>
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
        <FormField label="Filter by status">
          <Select
            selectedOption={selectedStatus}
            onChange={({ detail }) => setSelectedStatus(detail.selectedOption)}
            options={[
              { value: 'open', label: 'Open (no status)' },
              ...MITIGATION_STATUSES.map((s) => ({ value: s.value, label: s.label })),
            ]}
            placeholder="All statuses"
          />
        </FormField>
        <Box padding={{ top: 'l' }}>
          <Button
            variant="link"
            onClick={() => {
              setSelectedThreat(null);
              setSelectedRemediation(null);
              setSelectedPriority(null);
              setSelectedStatus(null);
            }}
            disabled={!isFiltered}
          >
            Clear filters
          </Button>
        </Box>
      </Grid>

      {/* Mitigations Table */}
      <Table<GlobalAggregatedMitigation>
        columnDefinitions={MITIGATION_COLUMNS}
        items={sortedMitigations}
        sortingColumn={sortingColumn ?? undefined}
        sortingDescending={sortingDescending}
        onSortingChange={({ detail }) => {
          setSortingColumn(detail.sortingColumn);
          setSortingDescending(detail.isDescending ?? false);
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
function Section({ title, children }: { title: string; children: ReactNode }) {
  return <Container header={<Header variant="h3">{title}</Header>}>{children}</Container>;
}

function KeyValue({ label, children }: { label: string; children?: ReactNode }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <div>{children || '—'}</div>
    </div>
  );
}

function BadgeList({ items, color = 'blue' }: { items?: string[]; color?: BadgeProps['color'] }) {
  if (!items || items.length === 0) return <Box color="text-status-inactive">{'—'}</Box>;
  return (
    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
      {items.map((item, i) => (
        <Badge key={i} color={color}>{item}</Badge>
      ))}
    </div>
  );
}

function BulletList({ items }: { items?: string[] }) {
  if (!items || items.length === 0) return <Box color="text-status-inactive">{'—'}</Box>;
  return (
    <ul style={{ margin: 0, paddingLeft: '20px' }}>
      {items.map((item, i) => (
        <li key={i} style={{ marginBottom: '6px', lineHeight: '1.5' }}>{item}</li>
      ))}
    </ul>
  );
}

interface ScannerContext {
  description?: string;
  cloud_provider?: string;
  industry?: string;
  services?: string[];
  files_analyzed?: string[];
  files_skipped_reason?: string[];
  auth_mechanisms?: string[];
  critical_findings?: string[];
  data_flows?: string[];
  trust_boundaries?: string[];
  interviewer_summary?: string;
  interviewer_confidence?: string;
  user_context?: Record<string, unknown> & {
    deployment_state?: string;
    environment_type?: string;
    industry?: string;
    data_sensitivity?: string;
    primary_threat_concern?: string;
    compliance_requirements?: string;
    studio_credential_model?: string;
    threat_model_focus?: string[];
    existing_controls_status?: Record<string, string>;
  };
  security_controls?: Record<string, string>;
  [key: string]: unknown;
}

interface ProjectInfo {
  application_name?: string;
  short_summary?: string;
  industry?: string;
  deployment_environment?: string;
  [key: string]: unknown;
}

// ─── Application Overview Tab ───
function ApplicationOverviewTab({
  scannerContext,
  projectInfo,
}: {
  scannerContext?: ScannerContext | null;
  projectInfo?: ProjectInfo | null;
}) {
  const ctx = scannerContext || {};
  const info = projectInfo || {};
  const userCtx = ctx.user_context || {};
  const secControls = ctx.security_controls || {};

  const deploymentType =
    userCtx.deployment_state ||
    userCtx.environment_type ||
    (ctx.cloud_provider ? `${ctx.cloud_provider.toUpperCase()} deployment` : null) ||
    info.deployment_environment ||
    null;

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
              <ExpandableSection
                headerText={`${ctx.files_skipped_reason.length} file${ctx.files_skipped_reason.length !== 1 ? 's' : ''} or director${ctx.files_skipped_reason.length !== 1 ? 'ies' : 'y'} skipped`}
                variant="footer"
              >
                <BulletList items={ctx.files_skipped_reason} />
              </ExpandableSection>
            )}
          </SpaceBetween>
        ) : (
          <Box color="text-status-inactive">{'—'}</Box>
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
                    <KeyValue key={key} label={key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}>
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
              Confidence:{' '}
              <Badge color={ctx.interviewer_confidence === 'high' ? 'green' : ctx.interviewer_confidence === 'medium' ? 'blue' : 'grey'}>
                {ctx.interviewer_confidence}
              </Badge>
            </Box>
          )}
        </Container>
      )}

      {/* Security controls */}
      {Object.keys(secControls).length > 0 && (
        <Section title="Security controls observed">
          <ColumnLayout columns={2} variant="text-grid">
            {Object.entries(secControls).map(([key, val]) => (
              <KeyValue key={key} label={key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}>
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

interface OverviewTableItem {
  idx: number;
  threat_id: string;
  threat_category: string;
  priority: string;
  threat_statement: string;
  threatSource: string;
  affected_components: string[];
  mitigations: AggregatedMitigation[];
  mapping_count: number;
  step_count: number;
}

type OverviewColumn = TableProps.ColumnDefinition<OverviewTableItem>;

// ─── Overview Tab Content ───
function OverviewTab({
  tableItems,
  appId,
  versionId,
}: {
  tableItems: OverviewTableItem[];
  appId: string;
  versionId: string;
}) {
  const router = useRouter();
  const COLUMN_DEFINITIONS: OverviewColumn[] = [
    {
      id: 'threat_id',
      header: 'ID',
      cell: (item) => {
        const href = `/applications/${appId}/versions/${versionId}/threats/${item.idx}`;
        return (
          <Link
            href={href}
            onFollow={(e) => {
              e.preventDefault();
              router.push(href);
            }}
          >
            <Box fontWeight="bold" display="inline">
              {item.threat_id}
            </Box>
          </Link>
        );
      },
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
            <div style={{ fontSize: '12px', color: '#5f6b7a', marginTop: '2px' }}>{item.threat_statement}</div>
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
        if (comps.length === 0) return '—';
        return (
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {comps.slice(0, 4).map((c, i) => (
              <Badge key={i} color="blue">{c}</Badge>
            ))}
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
        if (count === 0) return <Box color="text-status-inactive">{'—'}</Box>;
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
          onClick={() => router.push(`/applications/${appId}/versions/${versionId}/threats/${item.idx}`)}
        >
          See attack tree
        </Button>
      ),
      width: 150,
    },
  ];

  return (
    <Table<OverviewTableItem>
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
export default function ThreatModelSummaryView() {
  const { appId, versionId } = useRealParams<{ appId: string; versionId: string }>(
    '/applications/[appId]/versions/[versionId]',
  );
  const router = useRouter();
  const searchParams = useSearchParams();
  const [data, setData] = useState<SummaryData | null>(null);
  const [appName, setAppName] = useState<string>(appId);
  // True once we've confirmed a persistent app record owns this appId — at
  // that point we stop trusting project_info.application_name from the run
  // data, which can be a stale folder basename.
  const [persistentAppLoaded, setPersistentAppLoaded] = useState(false);
  const [versionLabel, setVersionLabel] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [frameworkCatalog, setFrameworkCatalog] = useState<FrameworkCatalog>({});
  // Mitigation overrides live at the page level so they survive when the
  // user switches between Application / Threats / Mitigations tabs (Cloudscape
  // Tabs unmounts the inactive tab body, which would otherwise wipe local
  // state on every tab swap).
  const [overrides, setOverrides] = useState<Record<string, MitigationOverride>>({});

  const activeTab = searchParams.get('tab') || 'application';

  useEffect(() => {
    let cancelled = false;
    async function fetchVersion() {
      try {
        setLoading(true);
        setError(null);
        const response = await fetch(
          `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/data`,
        );
        if (!response.ok) throw new Error(`Failed to load (HTTP ${response.status})`);
        const json = (await response.json()) as SummaryData;
        if (cancelled) return;
        setData(json);
        // Only use the run-data app name for legacy folder-derived apps
        // that have no persistent record.
        if (!persistentAppLoaded) {
          if (json.project_info?.application_name) setAppName(json.project_info.application_name);
          else if (json.application_name) setAppName(json.application_name);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchVersion();
    return () => {
      cancelled = true;
    };
  }, [appId, versionId, persistentAppLoaded]);

  // Load mitigation overrides once at page level so they persist across
  // tab swaps. Mutations from the editor go through onOverrideSaved /
  // onOverrideCleared which update this same state directly.
  useEffect(() => {
    let cancelled = false;
    getMitigationOverrides(appId, versionId)
      .then((d) => {
        if (!cancelled && d?.overrides) setOverrides(d.overrides);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [appId, versionId]);

  // Load the framework catalog once so we can render run_metadata.frameworks
  // with friendly names (e.g. "MITRE ATT&CK Enterprise") instead of keys.
  useEffect(() => {
    let cancelled = false;
    getFrameworks()
      .then((d) => {
        if (!cancelled && d?.frameworks) setFrameworkCatalog(d.frameworks);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
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
      .catch(() => {
        /* keep legacy fallback */
      });
    return () => {
      cancelled = true;
    };
  }, [appId]);

  // Resolve a friendly label for the current version ("Latest" when the URL
  // param is literal "latest"; otherwise "Version N" pulled from the list).
  useEffect(() => {
    let cancelled = false;
    if (versionId === 'latest') {
      setVersionLabel('Latest');
      return () => {
        cancelled = true;
      };
    }
    getApplicationVersions(appId)
      .then(({ versions = [] }) => {
        if (cancelled) return;
        const match = versions.find((v) => v.id === versionId);
        setVersionLabel(match?.display_name || versionId);
      })
      .catch(() => {
        if (!cancelled) setVersionLabel(versionId);
      });
    return () => {
      cancelled = true;
    };
  }, [appId, versionId]);

  const attackTrees = data?.attack_trees || [];
  const threats = data?.threats || [];

  const tableItems = useMemo<OverviewTableItem[]>(() => {
    return attackTrees.map((tree, idx) => ({
      idx,
      threat_id: tree.threat_id || `Threat ${idx + 1}`,
      threat_category: tree.threat_category || 'Unknown',
      priority: tree.priority != null && tree.priority !== '' ? String(tree.priority) : '—',
      threat_statement: tree.threat_statement || tree.threat_description || '',
      threatSource: (tree.threatSource as string) || '',
      affected_components: getAffectedComponents(tree, threats),
      mitigations: aggregateMitigations(tree),
      mapping_count: (tree.mapping_count as number) || (tree.ttc_mappings || []).length,
      step_count: (tree.attack_steps || []).length,
    }));
  }, [attackTrees, threats]);

  // Globally-deduplicated mitigation count (consistent with mitigations tab)
  const globalMitigations = useMemo(
    () => aggregateAllMitigations(attackTrees, threats),
    [attackTrees, threats],
  );

  return (
    <AppShell
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
        <Box textAlign="center" padding="l">
          <Spinner size="large" />
        </Box>
      ) : data ? (
        <SpaceBetween size="m">
          <Header
            variant="h1"
            actions={
              <ExportButton
                // SummaryData and ThreatModelSummary differ only in that the
                // former lets project_info be null (vs undefined). ExportButton
                // reads only attack_trees, so the shapes are runtime-compatible
                // — reconcile the null-vs-undefined gap at this boundary.
                summaryData={data as ThreatModelSummary}
                appId={appId}
                versionId={versionId}
                appName={appName}
                versionLabel={versionLabel}
              />
            }
          >
            Threat Model Summary
          </Header>
          <OnboardingBanner />
          <SummaryBar data={data} totalMitigations={globalMitigations.length} />
          <Tabs
            activeTabId={activeTab}
            onChange={({ detail }) => {
              const next = new URLSearchParams(searchParams.toString());
              next.set('tab', detail.activeTabId);
              router.push(`?${next.toString()}`);
            }}
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
                content: <OverviewTab tableItems={tableItems} appId={appId} versionId={versionId} />,
              },
              {
                id: 'mitigations',
                label: `Mitigations (${globalMitigations.length})`,
                content: (
                  <MitigationsTab
                    attackTrees={attackTrees}
                    threats={threats}
                    appId={appId}
                    versionId={versionId}
                    overrides={overrides}
                    onOverrideSaved={(name, override) =>
                      setOverrides((prev) => ({ ...prev, [name]: override }))
                    }
                    onOverrideCleared={(name) =>
                      setOverrides((prev) => {
                        const next = { ...prev };
                        delete next[name];
                        return next;
                      })
                    }
                  />
                ),
              },
            ]}
          />
          <RunMetaBar meta={data?.run_metadata} frameworkCatalog={frameworkCatalog} />
        </SpaceBetween>
      ) : null}
    </AppShell>
  );
}
