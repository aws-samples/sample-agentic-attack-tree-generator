'use client';

import { useState } from 'react';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Textarea from '@cloudscape-design/components/textarea';
import Select from '@cloudscape-design/components/select';
import type { SelectProps } from '@cloudscape-design/components/select';
import TokenGroup from '@cloudscape-design/components/token-group';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import type { z } from 'zod';
import {
  CIA_DEFAULT_ORDER,
  DataSensitivity,
  type BusinessContext,
  type CiaObjectiveT,
} from '@threatforest/types';
import CiaPriorityList from './CiaPriorityList';

/** Inferred enum type for `data_sensitivity` (the package exports the schema only). */
type DataSensitivityT = z.infer<typeof DataSensitivity>;

/**
 * Editable form draft. The strict `BusinessContext` requires a valid
 * `data_sensitivity` enum value, but the form starts blank (sentinel `''`)
 * before the user has chosen, so the draft loosens that single field. Call
 * {@link validateBusinessContext} before treating a draft as a real context.
 */
export type BusinessContextDraft = Omit<BusinessContext, 'data_sensitivity'> & {
  data_sensitivity: DataSensitivityT | '';
};

export interface BusinessContextFormProps {
  value: BusinessContextDraft;
  onChange: (next: BusinessContextDraft) => void;
  errors?: Partial<Record<keyof BusinessContextDraft, string>>;
}

/**
 * Re-exported for callers that render CIA ordering outside the form. Kept in
 * sync with ``CIA_DEFAULT_ORDER`` in ``src/server/models.py``.
 */
export { CIA_DEFAULT_ORDER };

/**
 * Treat any malformed cia_priority (missing, wrong length, dupes, unknown
 * values) as if the user hadn't ranked yet — fall back to the canonical
 * ordering so the drag UI never renders in a broken state.
 */
export function normaliseCiaPriority(input: unknown): CiaObjectiveT[] {
  const known = new Set<CiaObjectiveT>(CIA_DEFAULT_ORDER);
  if (!Array.isArray(input)) return [...CIA_DEFAULT_ORDER];
  const seen = new Set<CiaObjectiveT>();
  const ordered: CiaObjectiveT[] = [];
  for (const v of input) {
    if (known.has(v as CiaObjectiveT) && !seen.has(v as CiaObjectiveT)) {
      seen.add(v as CiaObjectiveT);
      ordered.push(v as CiaObjectiveT);
    }
  }
  // Append any objectives the user's list omitted, preserving canonical order.
  for (const v of CIA_DEFAULT_ORDER) {
    if (!seen.has(v)) ordered.push(v);
  }
  return ordered;
}

/**
 * Option lists mirror the BusinessContext Pydantic Literals in
 * src/server/models.py. "Unknown" is offered as a low-friction sentinel for
 * users who can't commit to a value up front — the field stays required but
 * the choice is explicit.
 */
export const DATA_SENSITIVITY_OPTIONS: ReadonlyArray<{
  value: DataSensitivityT;
  label: string;
}> = [
  { value: 'public',              label: 'Public — no access restrictions' },
  { value: 'internal',            label: 'Internal — staff or partners only' },
  { value: 'confidential',        label: 'Confidential — limited business exposure' },
  { value: 'highly_confidential', label: 'Highly confidential — restricted to a named group, severe damage on leak' },
  { value: 'pii',                 label: 'PII — personally identifiable information' },
  { value: 'phi',                 label: 'PHI — protected health information' },
  { value: 'regulated_financial', label: 'Regulated financial — PCI / SOX / similar' },
  { value: 'unknown',             label: "Unknown — I don't know yet" },
];

/**
 * Editable form for a BusinessContext object. Controlled — the caller owns
 * state via `value` / `onChange`. Emits the full context draft on every
 * change so the parent can drive validation and submission.
 */
export default function BusinessContextForm({
  value,
  onChange,
  errors = {},
}: BusinessContextFormProps) {
  const patch = (fields: Partial<BusinessContextDraft>) =>
    onChange({ ...value, ...fields });

  const sensitivityOption =
    DATA_SENSITIVITY_OPTIONS.find((o) => o.value === value.data_sensitivity) ?? null;
  const ciaPriority = normaliseCiaPriority(value.cia_priority);

  const [frameworkDraft, setFrameworkDraft] = useState('');
  const frameworks = value.regulatory_frameworks || [];

  const addFramework = () => {
    const next = frameworkDraft.trim();
    if (!next) return;
    if (frameworks.some((f) => f.toLowerCase() === next.toLowerCase())) {
      setFrameworkDraft('');
      return;
    }
    patch({ regulatory_frameworks: [...frameworks, next] });
    setFrameworkDraft('');
  };

  const removeFramework = (idx: number) => {
    patch({
      regulatory_frameworks: frameworks.filter((_, i) => i !== idx),
    });
  };

  return (
    <SpaceBetween size="l">
      <FormField
        label="Application description"
        description="One or two sentences describing what the application does and its business purpose. Shared with the scanner agent as authoritative context."
        errorText={errors.description}
      >
        <Textarea
          value={value.description || ''}
          onChange={({ detail }) => patch({ description: detail.value })}
          placeholder="A healthcare intake API that stores patient records and integrates with an external EHR…"
          rows={3}
        />
      </FormField>

      <FormField
        label="Regulatory frameworks"
        description="Frameworks this application must comply with. Seeded into scanner context and used to weight threat analysis."
        errorText={errors.regulatory_frameworks}
      >
        <SpaceBetween size="xs">
          {frameworks.length > 0 && (
            <TokenGroup
              items={frameworks.map((f) => ({ label: f, dismissLabel: `Remove ${f}` }))}
              onDismiss={({ detail }) => removeFramework(detail.itemIndex)}
            />
          )}
          <div style={{ display: 'flex', gap: 8 }}>
            <div style={{ flex: 1 }}>
              <Input
                value={frameworkDraft}
                onChange={({ detail }) => setFrameworkDraft(detail.value)}
                onKeyDown={(e) => {
                  if (e.detail.key === 'Enter') {
                    e.preventDefault();
                    addFramework();
                  }
                }}
                placeholder="e.g. SOC2, HIPAA, PCI-DSS"
              />
            </div>
            <Button iconName="add-plus" onClick={addFramework} ariaLabel="Add framework">
              Add
            </Button>
          </div>
        </SpaceBetween>
      </FormField>

      <FormField
        label="Data sensitivity"
        description="Highest-classification data the application handles."
        errorText={errors.data_sensitivity}
      >
        <Select
          selectedOption={sensitivityOption as SelectProps.Option | null}
          onChange={({ detail }) =>
            patch({ data_sensitivity: detail.selectedOption.value as DataSensitivityT })
          }
          options={DATA_SENSITIVITY_OPTIONS as unknown as SelectProps.Options}
          placeholder="Choose a sensitivity level"
        />
      </FormField>

      <FormField
        label="CIA priority"
        description="Rank confidentiality, integrity, and availability for this application — drag the rows to reorder."
        errorText={errors.cia_priority}
      >
        <CiaPriorityList
          value={ciaPriority}
          onChange={(next) => patch({ cia_priority: next })}
        />
      </FormField>
    </SpaceBetween>
  );
}

/**
 * Return an empty BusinessContext draft — useful for seeding page state before
 * the user has typed anything. ``cia_priority`` is initialised to the canonical
 * default ordering rather than empty because the drag UI always renders three
 * rows; the user's expected interaction is to drag them, not to pick from
 * scratch.
 */
export function emptyBusinessContext(): BusinessContextDraft {
  return {
    description: '',
    regulatory_frameworks: [],
    data_sensitivity: '',
    cia_priority: [...CIA_DEFAULT_ORDER],
  };
}

/**
 * Validate a BusinessContext draft. Returns an errors object keyed by field —
 * empty when the context is valid.
 */
export function validateBusinessContext(
  ctx: BusinessContextDraft,
): Partial<Record<keyof BusinessContextDraft, string>> {
  const errors: Partial<Record<keyof BusinessContextDraft, string>> = {};
  if (!ctx.description || !ctx.description.trim()) {
    errors.description = 'Description is required.';
  }
  if (!ctx.regulatory_frameworks || ctx.regulatory_frameworks.length === 0) {
    errors.regulatory_frameworks =
      "Add at least one framework (use 'None' if this app isn't subject to regulation).";
  }
  if (!ctx.data_sensitivity) {
    errors.data_sensitivity = 'Choose a data sensitivity level.';
  }
  const cia = ctx.cia_priority;
  if (!Array.isArray(cia) || cia.length !== 3 || new Set(cia).size !== 3) {
    errors.cia_priority = 'Rank all three CIA objectives.';
  }
  return errors;
}
