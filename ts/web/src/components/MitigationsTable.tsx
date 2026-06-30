'use client';

import { useMemo, useState } from 'react';
import Table, { type TableProps } from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import Badge, { type BadgeProps } from '@cloudscape-design/components/badge';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import FormField from '@cloudscape-design/components/form-field';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Grid from '@cloudscape-design/components/grid';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import { aggregateMitigations, type AggregatedMitigation, type ReportAttackTree } from '@/utils/mitigation-aggregator';
import { buildTechniqueUrl } from '@/utils/technique-url';
import {
  filterMitigations,
  getUniqueAttackSteps,
  getUniqueMitigationNames,
  type FilterableMitigation,
} from '@/utils/mitigation-filter';
import { renderFormattedText } from '@/utils/text-formatter';
import { mitigationToMarkdown } from '@/utils/mitigation-markdown';
import { statusInfo } from '@/utils/mitigation-status';

type ColumnDefinition = TableProps.ColumnDefinition<AggregatedMitigation>;

/** A single evidence record as it appears in the (loose) report bundle. */
interface EvidenceItem {
  source_type?: string;
  source_ref?: string;
  relevance?: string;
}

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

const COLUMN_DEFINITIONS: ColumnDefinition[] = [
  {
    id: 'priority',
    header: 'Priority',
    cell: (item) => {
      const p = item.priority;
      const label =
        typeof p === 'number' ? ['', 'Critical', 'High', 'Medium'][p] || `P${p}` : p || '—';
      return (
        <Badge color={PRIORITY_COLORS[String(p)] || PRIORITY_COLORS[String(p).toLowerCase()] || 'grey'}>
          {label}
        </Badge>
      );
    },
    sortingField: 'priority',
    width: 90,
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
    minWidth: 300,
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
      const evidence = (item.evidence || []) as EvidenceItem[];
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
                {e.relevance && (
                  <div style={{ color: '#687078', fontStyle: 'italic' }}>{e.relevance}</div>
                )}
              </div>
            ))}
          </div>
        </ExpandableSection>
      );
    },
    minWidth: 150,
  },
];

/**
 * Read-only Status column for the per-threat MitigationsTable. Mirrors what
 * the user sees on the Mitigations tab but without the editor — edits live
 * in one place. The "Edit on the Mitigations tab" link opens a new tab so
 * the user doesn't lose their place inside the per-threat view.
 */
function makeStatusColumn(appId?: string, versionId?: string): ColumnDefinition {
  return {
    id: 'status',
    header: 'Status',
    cell: (item) => {
      const info = statusInfo(item.overrideStatus);
      const editHref =
        appId && versionId
          ? `/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}?tab=mitigations`
          : null;
      return (
        <div style={{ minWidth: 160 }}>
          {info ? (
            <SpaceBetween size="xxs">
              <Badge color={info.color as BadgeProps['color']}>{info.label}</Badge>
              {item.overrideComment && (
                <Box variant="small" color="text-body-secondary">
                  {item.overrideComment}
                </Box>
              )}
              {editHref && (
                <a
                  href={editHref}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ fontSize: 12, color: '#0972d3' }}
                >
                  Edit on the Mitigations tab ↗
                </a>
              )}
            </SpaceBetween>
          ) : (
            <Box variant="small" color="text-status-inactive">
              Open
              {editHref && (
                <>
                  {' — '}
                  <a
                    href={editHref}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: '#0972d3' }}
                  >
                    Set status ↗
                  </a>
                </>
              )}
            </Box>
          )}
        </div>
      );
    },
    width: 220,
  };
}

/**
 * Attack-step column factory. Lives outside COLUMN_DEFINITIONS because the
 * cell renderer needs to close over the page-level onFocusStep callback so
 * clicking a step badge can pan the ReactFlow viewer to the matching node.
 */
function makeAttackStepsColumn(onFocusStep?: (nodeId: string) => void): ColumnDefinition {
  return {
    id: 'attackSteps',
    header: 'Attack Steps',
    cell: (item) => {
      // Prefer the new {label, nodeId} refs so clicks can focus the matching
      // ReactFlow node; fall back to legacy string-only attackSteps for older
      // aggregator output and tests.
      const refs =
        Array.isArray(item.attackStepRefs) && item.attackStepRefs.length
          ? item.attackStepRefs
          : (item.attackSteps || []).map((label) => ({ label, nodeId: '' }));
      if (refs.length === 0) return '—';
      return (
        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
          {refs.map(({ label, nodeId }, idx) => {
            const focusable = !!(onFocusStep && nodeId);
            return (
              <button
                key={`${label}-${idx}`}
                type="button"
                onClick={() => focusable && onFocusStep?.(nodeId)}
                disabled={!focusable}
                title={focusable ? `Show ${label} on the attack tree` : label}
                onMouseEnter={(e) => {
                  if (focusable) e.currentTarget.style.transform = 'translateY(-1px)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                }}
                style={{
                  background: 'transparent',
                  border: 0,
                  padding: 0,
                  cursor: focusable ? 'pointer' : 'default',
                  font: 'inherit',
                  display: 'inline-block',
                  transition: 'transform 0.1s ease',
                }}
              >
                {/* Block pointer events on the Badge so the cursor falls
                    through to the parent <button>. Cloudscape Badge sets its
                    own cursor that otherwise wins on hover. Click handling
                    stays on the button, which is unaffected. */}
                <span style={{ pointerEvents: 'none' }}>
                  <Badge color="blue">{label}</Badge>
                </span>
              </button>
            );
          })}
        </div>
      );
    },
    width: 250,
    minWidth: 200,
  };
}

export interface MitigationsTableProps {
  /** The loose report-bundle attack-tree shape this table aggregates over. */
  attackTree: ReportAttackTree | null | undefined;
  /** Click handler that pans the AttackFlowViewer to the matching node. */
  onFocusStep?: (nodeId: string) => void;
  appId?: string;
  versionId?: string;
}

const REMEDIATION_ORDER: Record<string, number> = {
  quick_win: 0,
  short_term: 1,
  medium_term: 2,
  long_term: 3,
  monitoring: 4,
};

export default function MitigationsTable({
  attackTree,
  onFocusStep,
  appId,
  versionId,
}: MitigationsTableProps) {
  const mitigations = useMemo(() => aggregateMitigations(attackTree), [attackTree]);

  // Compose the static columns with the read-only Status column and the
  // attack-step column that wires clicks to the AttackFlowViewer above. Both
  // need values from the parent so they're built per-render.
  //
  // Column order matches the dedup view: ...prefix · Mitigation · Status · ...
  // — Status sits next to the name so users can read the disposition before
  // they look at the Mapped TTP / Evidence / Attack Steps detail.
  const allColumns = useMemo<ColumnDefinition[]>(() => {
    const nameIdx = COLUMN_DEFINITIONS.findIndex((c) => c.id === 'name');
    const insertAt = nameIdx >= 0 ? nameIdx + 1 : COLUMN_DEFINITIONS.length;
    return [
      ...COLUMN_DEFINITIONS.slice(0, insertAt),
      makeStatusColumn(appId, versionId),
      ...COLUMN_DEFINITIONS.slice(insertAt),
      makeAttackStepsColumn(onFocusStep),
    ];
  }, [appId, versionId, onFocusStep]);

  // --- Column widths state for resizable columns ---
  const [columnWidths, setColumnWidths] = useState<Record<string, number>>(() =>
    allColumns.reduce<Record<string, number>>((acc, col) => {
      if (col.id && col.width) acc[col.id] = col.width as number;
      return acc;
    }, {}),
  );

  const handleColumnWidthsChange: TableProps['onColumnWidthsChange'] = ({ detail }) => {
    const updated: Record<string, number> = {};
    detail.widths.forEach((width, index) => {
      const col = allColumns[index];
      if (col?.id) updated[col.id] = width;
    });
    setColumnWidths((prev) => ({ ...prev, ...updated }));
  };

  // Apply current widths to column definitions
  const resizableColumns = useMemo<ColumnDefinition[]>(
    () =>
      allColumns.map((col) => ({
        ...col,
        width: (col.id ? columnWidths[col.id] : undefined) || col.width,
      })),
    [allColumns, columnWidths],
  );

  // --- Task 2.1: Filter state ---
  const [selectedAttackStep, setSelectedAttackStep] = useState<SelectProps.Option | null>(null);
  const [selectedMitigation, setSelectedMitigation] = useState<SelectProps.Option | null>(null);

  // Derive dropdown options
  // The mitigation-filter helpers read the structural FilterableMitigation
  // shape (name + attackSteps + an index signature). AggregatedMitigation
  // carries those fields but no index signature, so we narrow to the helper's
  // contract at the call boundary and widen the result back.
  const filterable = mitigations as unknown as FilterableMitigation[];

  const attackStepOptions = useMemo<SelectProps.Option[]>(
    () => getUniqueAttackSteps(filterable).map((s) => ({ label: s, value: s })),
    [filterable],
  );

  const mitigationOptions = useMemo<SelectProps.Option[]>(
    () => getUniqueMitigationNames(filterable).map((n) => ({ label: n, value: n })),
    [filterable],
  );

  // Derive filtered mitigations
  const filteredMitigations = useMemo(
    () =>
      filterMitigations(filterable, {
        attackStep: selectedAttackStep?.value ?? null,
        mitigationName: selectedMitigation?.value ?? null,
      }) as unknown as AggregatedMitigation[],
    [filterable, selectedAttackStep, selectedMitigation],
  );

  // --- Sorting state ---
  // onSortingChange hands back a SortingColumn<T> (a narrower projection of the
  // column def), so the state stores that shape rather than the full
  // ColumnDefinition. The initial ColumnDefinition is assignable to it.
  const [sortingColumn, setSortingColumn] = useState<
    TableProps.SortingColumn<AggregatedMitigation>
  >(COLUMN_DEFINITIONS[0]!); // default: priority
  const [sortingDescending, setSortingDescending] = useState(false);

  const sortedMitigations = useMemo(() => {
    const field = sortingColumn?.sortingField as keyof AggregatedMitigation | undefined;
    if (!field) return filteredMitigations;
    const sorted = [...filteredMitigations].sort((a, b) => {
      const aVal = a[field] ?? '';
      const bVal = b[field] ?? '';
      if (field === 'remediationType') {
        return (
          (REMEDIATION_ORDER[String(aVal)] ?? 99) - (REMEDIATION_ORDER[String(bVal)] ?? 99)
        );
      }
      if (typeof aVal === 'number' && typeof bVal === 'number') return aVal - bVal;
      return String(aVal).localeCompare(String(bVal));
    });
    return sortingDescending ? sorted.reverse() : sorted;
  }, [filteredMitigations, sortingColumn, sortingDescending]);

  // Header counter: show "filtered of total" when a filter is active
  const isFiltered = selectedAttackStep !== null || selectedMitigation !== null;
  const counterText = isFiltered
    ? `(${filteredMitigations.length} of ${mitigations.length})`
    : `(${mitigations.length})`;

  // --- Task 2.2: Filter bar handlers ---
  const handleAttackStepChange: SelectProps['onChange'] = ({ detail }) => {
    setSelectedAttackStep(detail.selectedOption);
    setSelectedMitigation(null);
  };

  const handleMitigationChange: SelectProps['onChange'] = ({ detail }) => {
    setSelectedMitigation(detail.selectedOption);
    setSelectedAttackStep(null);
  };

  const handleClearFilters = () => {
    setSelectedAttackStep(null);
    setSelectedMitigation(null);
  };

  return (
    <SpaceBetween size="m">
      {/* Filter Bar */}
      <Grid gridDefinition={[{ colspan: 4 }, { colspan: 4 }, { colspan: 4 }]}>
        <FormField label="Filter by attack step">
          <Select
            selectedOption={selectedAttackStep}
            onChange={handleAttackStepChange}
            options={attackStepOptions}
            placeholder="All attack steps"
            disabled={attackStepOptions.length === 0}
            data-testid="attack-step-filter"
          />
        </FormField>
        <FormField label="Filter by mitigation">
          <Select
            selectedOption={selectedMitigation}
            onChange={handleMitigationChange}
            options={mitigationOptions}
            placeholder="All mitigations"
            disabled={mitigationOptions.length === 0}
            data-testid="mitigation-filter"
          />
        </FormField>
        <Box padding={{ top: 'l' }}>
          <Button
            variant="link"
            onClick={handleClearFilters}
            disabled={!isFiltered}
            data-testid="clear-filters-button"
          >
            Clear filters
          </Button>
        </Box>
      </Grid>

      {/* Table */}
      <Table<AggregatedMitigation>
        columnDefinitions={resizableColumns}
        items={sortedMitigations}
        sortingColumn={sortingColumn}
        sortingDescending={sortingDescending}
        onSortingChange={({ detail }) => {
          setSortingColumn(detail.sortingColumn);
          setSortingDescending(detail.isDescending ?? false);
        }}
        resizableColumns
        onColumnWidthsChange={handleColumnWidthsChange}
        header={
          <Header variant="h3" counter={counterText}>
            Mitigations Summary
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
        data-testid="mitigations-table"
      />
    </SpaceBetween>
  );
}
