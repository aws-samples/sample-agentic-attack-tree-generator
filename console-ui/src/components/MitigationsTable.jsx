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
import ExpandableSection from '@cloudscape-design/components/expandable-section';
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
    cell: (item) => {
      if (item.name.length <= 80) return <span style={{ fontSize: '13px' }}>{item.name}</span>;
      return (
        <ExpandableSection headerText={item.name.slice(0, 80) + '…'} variant="footer" headerAriaLabel="Expand mitigation">
          <Box fontSize="body-s" color="text-body-secondary">{item.name}</Box>
        </ExpandableSection>
      );
    },
    sortingField: "name",
    width: 250,
    minWidth: 180,
  },
  {
    id: "description",
    header: "Implementation Guidance",
    cell: (item) => {
      if (!item.description) return "—";
      if (item.description.length <= 100) return <span style={{ fontSize: '13px' }}>{item.description}</span>;
      const brief = item.description.slice(0, 100) + '…';
      const steps = item.description.split(/(?=\d+\.\s)/).filter(Boolean);
      return (
        <ExpandableSection headerText={brief} variant="footer" headerAriaLabel="Expand guidance">
          {steps.length > 1 ? (
            <ol style={{ margin: '4px 0', paddingLeft: '20px', fontSize: '13px', lineHeight: '1.6' }}>
              {steps.map((s, i) => (
                <li key={i} style={{ marginBottom: '6px' }}>{s.replace(/^\d+\.\s*/, '')}</li>
              ))}
            </ol>
          ) : (
            <Box fontSize="body-s" color="text-body-secondary">{item.description}</Box>
          )}
        </ExpandableSection>
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
      const brief = `${item.evidence.length} source${item.evidence.length > 1 ? 's' : ''}: ${item.evidence[0].source_type}`;
      return (
        <ExpandableSection headerText={brief} variant="footer" headerAriaLabel="Expand evidence">
          <div style={{ fontSize: '12px' }}>
            {item.evidence.map((e, i) => (
              <div key={i} style={{ marginBottom: '6px', padding: '4px 0', borderBottom: i < item.evidence.length - 1 ? '1px solid #e9ebed' : 'none' }}>
                <Badge color="grey">{e.source_type}</Badge>{' '}
                <span style={{ color: '#5f6b7a' }}>{e.source_ref}</span>
                {e.relevance && <div style={{ color: '#687078', fontStyle: 'italic', marginTop: '2px' }}>{e.relevance}</div>}
              </div>
            ))}
          </div>
        </ExpandableSection>
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


export default function MitigationsTable({ attackTree }) {
  const mitigations = useMemo(() => {
    const raw = aggregateMitigations(attackTree);
    // Sort by priority: 1 (critical) first, null/undefined last
    const order = { 1: 0, 2: 1, 3: 2, critical: 0, high: 1, medium: 2, low: 3 };
    return raw.sort((a, b) => (order[a.priority] ?? 99) - (order[b.priority] ?? 99));
  }, [attackTree]);

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
        columnDefinitions={COLUMN_DEFINITIONS}
        items={filteredMitigations}
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
