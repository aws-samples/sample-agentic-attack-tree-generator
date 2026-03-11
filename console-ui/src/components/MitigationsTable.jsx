import React, { useMemo, useState } from 'react';
import Table from '@cloudscape-design/components/table';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import Select from '@cloudscape-design/components/select';
import FormField from '@cloudscape-design/components/form-field';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Grid from '@cloudscape-design/components/grid';
import Popover from '@cloudscape-design/components/popover';
import { aggregateMitigations } from '../utils/mitigation-aggregator';
import {
  filterMitigations,
  getUniqueAttackSteps,
  getUniqueMitigationNames,
} from '../utils/mitigation-filter';

const PRIORITY_COLORS = { 1: 'red', 2: 'red', 3: 'blue', high: 'red', critical: 'red', medium: 'blue', low: 'grey' };

const COLUMN_DEFINITIONS = [
  {
    id: "priority",
    header: "Priority",
    cell: (item) => {
      const p = item.priority;
      const label = typeof p === 'number' ? ['', 'Critical', 'High', 'Medium'][p] || `P${p}` : (p || '—');
      return <Badge color={PRIORITY_COLORS[p] || PRIORITY_COLORS[String(p).toLowerCase()] || 'grey'}>{label}</Badge>;
    },
    sortingField: "priority",
    width: 90,
  },
  {
    id: "name",
    header: "Mitigation",
    cell: (item) => item.name,
    sortingField: "name",
    width: 200,
    minWidth: 140,
  },
  {
    id: "description",
    header: "Implementation Guidance",
    cell: (item) => {
      if (!item.description) return "—";
      // Split numbered steps (1. xxx 2. xxx) into a list
      const steps = item.description.split(/(?=\d+\.\s)/).filter(Boolean);
      if (steps.length > 1) {
        return (
          <div style={{ whiteSpace: 'normal', wordBreak: 'break-word', fontSize: '13px', lineHeight: '1.7' }}>
            {steps.map((s, i) => {
              const stepText = s.replace(/^\d+\.\s*/, '');
              // Extract **bold title:** pattern
              const boldMatch = stepText.match(/^\*\*(.+?)\*\*[:\s]*(.*)/s);
              if (boldMatch) {
                const title = boldMatch[1];
                const detail = boldMatch[2].trim();
                // Also render inline `code` in detail
                return (
                  <div key={i} style={{ marginBottom: '4px' }}>
                    <Popover
                      position="right"
                      size="large"
                      triggerType="custom"
                      content={
                        <div style={{ maxWidth: 480, maxHeight: 320, overflow: 'auto', fontSize: '13px', lineHeight: '1.5', whiteSpace: 'normal', wordBreak: 'break-word' }}>
                          <div style={{ fontWeight: 700, marginBottom: 6, color: '#0972d3' }}>{title}</div>
                          <div style={{ color: '#414d5c' }}>{renderFormattedText(detail)}</div>
                        </div>
                      }
                    >
                      <span style={{ color: '#0972d3', cursor: 'pointer', fontWeight: 600, textDecoration: 'none', borderBottom: '1px dashed #0972d3' }}>
                        {i + 1}. {title}
                      </span>
                    </Popover>
                  </div>
                );
              }
              // Fallback for steps without bold pattern
              return (
                <div key={i} style={{ marginBottom: '4px' }}>
                  <Popover
                    position="right"
                    size="large"
                    triggerType="custom"
                    content={
                      <div style={{ maxWidth: 480, maxHeight: 320, overflow: 'auto', fontSize: '13px', lineHeight: '1.5', whiteSpace: 'normal', wordBreak: 'break-word', color: '#414d5c' }}>
                        {renderFormattedText(stepText)}
                      </div>
                    }
                  >
                    <span style={{ color: '#0972d3', cursor: 'pointer', textDecoration: 'none', borderBottom: '1px dashed #0972d3' }}>
                      {i + 1}. {stepText.length > 60 ? stepText.slice(0, 60) + '…' : stepText}
                    </span>
                  </Popover>
                </div>
              );
            })}
          </div>
        );
      }
      return (
        <div style={{ whiteSpace: "normal", wordBreak: "break-word" }}>
          {renderFormattedText(item.description)}
        </div>
      );
    },
    minWidth: 200,
  },
  {
    id: "technique",
    header: "ATT&CK Technique",
    cell: (item) => {
      if (!item.techniqueId) return "—";
      const url = `https://attack.mitre.org/techniques/${item.techniqueId.replace('.', '/')}/`;
      return <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: '#0972d3' }}>{item.techniqueId}</a>;
    },
    width: 130,
  },
  {
    id: "evidence",
    header: "Evidence",
    cell: (item) => {
      if (!item.evidence || item.evidence.length === 0) return "—";
      return (
        <div style={{ whiteSpace: "normal", wordBreak: "break-word" }}>
          {item.evidence.map((e, i) => (
            <div key={i} style={{ marginBottom: '4px', fontSize: '12px' }}>
              <Badge color="grey">{e.source_type}</Badge>{' '}
              <span style={{ color: '#5f6b7a' }}>{e.source_ref}</span>
              {e.relevance && <div style={{ color: '#687078', fontStyle: 'italic' }}>{e.relevance}</div>}
            </div>
          ))}
        </div>
      );
    },
    minWidth: 200,
  },
  {
    id: "attackSteps",
    header: "Attack Steps",
    cell: (item) =>
      item.attackSteps.length > 0 ? (
        <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
          {item.attackSteps.map((step) => (
            <Badge key={step} color="blue">{step}</Badge>
          ))}
        </div>
      ) : (
        "—"
      ),
    width: 250,
    minWidth: 200,
  },
];


/**
 * Render text with inline formatting:
 * - **bold** → <strong>
 * - `code` → <code>
 */
function renderFormattedText(text) {
  if (!text) return null;
  // Split on **bold** and `code` patterns, preserving delimiters
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={i} style={{ background: '#f2f3f3', padding: '1px 5px', borderRadius: 3, fontSize: '12px', fontFamily: 'monospace' }}>
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

export default function MitigationsTable({ attackTree }) {
  const mitigations = useMemo(() => aggregateMitigations(attackTree), [attackTree]);

  // --- Column widths state for resizable columns ---
  const [columnWidths, setColumnWidths] = useState(() =>
    COLUMN_DEFINITIONS.reduce((acc, col) => {
      if (col.width) acc[col.id] = col.width;
      return acc;
    }, {})
  );

  const handleColumnWidthsChange = ({ detail }) => {
    const updated = {};
    for (const w of detail.widths) {
      updated[w.id] = w.width;
    }
    setColumnWidths(prev => ({ ...prev, ...updated }));
  };

  // Apply current widths to column definitions
  const resizableColumns = useMemo(
    () =>
      COLUMN_DEFINITIONS.map(col => ({
        ...col,
        width: columnWidths[col.id] || col.width,
      })),
    [columnWidths]
  );

  // --- Task 2.1: Filter state ---
  const [selectedAttackStep, setSelectedAttackStep] = useState(null);
  const [selectedMitigation, setSelectedMitigation] = useState(null);

  // Derive dropdown options
  const attackStepOptions = useMemo(
    () =>
      getUniqueAttackSteps(mitigations).map((s) => ({ label: s, value: s })),
    [mitigations]
  );

  const mitigationOptions = useMemo(
    () =>
      getUniqueMitigationNames(mitigations).map((n) => ({ label: n, value: n })),
    [mitigations]
  );

  // Derive filtered mitigations
  const filteredMitigations = useMemo(
    () =>
      filterMitigations(mitigations, {
        attackStep: selectedAttackStep?.value ?? null,
        mitigationName: selectedMitigation?.value ?? null,
      }),
    [mitigations, selectedAttackStep, selectedMitigation]
  );

  // Header counter: show "filtered of total" when a filter is active
  const isFiltered = selectedAttackStep !== null || selectedMitigation !== null;
  const counterText = isFiltered
    ? `(${filteredMitigations.length} of ${mitigations.length})`
    : `(${mitigations.length})`;

  // --- Task 2.2: Filter bar handlers ---
  const handleAttackStepChange = ({ detail }) => {
    setSelectedAttackStep(detail.selectedOption);
    setSelectedMitigation(null);
  };

  const handleMitigationChange = ({ detail }) => {
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
        <Box padding={{ top: "l" }}>
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
      <Table
        columnDefinitions={resizableColumns}
        items={filteredMitigations}
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
