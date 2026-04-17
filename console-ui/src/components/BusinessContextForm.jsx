import React from 'react';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Textarea from '@cloudscape-design/components/textarea';
import Select from '@cloudscape-design/components/select';
import TokenGroup from '@cloudscape-design/components/token-group';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import ColumnLayout from '@cloudscape-design/components/column-layout';

/**
 * Option lists mirror the BusinessContext Pydantic Literals in
 * src/server/models.py. "Unknown" is offered as a low-friction sentinel for
 * users who can't commit to a value up front — the field stays required but
 * the choice is explicit.
 */
export const DATA_SENSITIVITY_OPTIONS = [
  { value: 'public',              label: 'Public — no access restrictions' },
  { value: 'internal',            label: 'Internal — staff or partners only' },
  { value: 'confidential',        label: 'Confidential — limited business exposure' },
  { value: 'pii',                 label: 'PII — personally identifiable information' },
  { value: 'phi',                 label: 'PHI — protected health information' },
  { value: 'regulated_financial', label: 'Regulated financial — PCI / SOX / similar' },
  { value: 'unknown',             label: "Unknown — I don't know yet" },
];

export const MAIN_CIA_RISK_OPTIONS = [
  { value: 'confidentiality', label: 'Confidentiality — leaks and data exposure are worst-case' },
  { value: 'integrity',       label: 'Integrity — tampering or corrupted data is worst-case' },
  { value: 'availability',    label: 'Availability — downtime or DoS is worst-case' },
  { value: 'unknown',         label: "Unknown — I don't know yet" },
];

/**
 * Editable form for a BusinessContext object. Controlled — the caller owns
 * state via `value` / `onChange`. Emits the full context object on every
 * change so the parent can drive validation and submission.
 *
 * The shape matches the backend ``BusinessContext`` model verbatim:
 *   {
 *     description: string,
 *     regulatory_frameworks: string[],
 *     data_sensitivity: <one of DATA_SENSITIVITY_OPTIONS.value>,
 *     main_cia_risk:    <one of MAIN_CIA_RISK_OPTIONS.value>,
 *   }
 */
export default function BusinessContextForm({ value, onChange, errors = {} }) {
  const patch = (fields) => onChange({ ...value, ...fields });

  const sensitivityOption =
    DATA_SENSITIVITY_OPTIONS.find((o) => o.value === value.data_sensitivity) ?? null;
  const ciaOption =
    MAIN_CIA_RISK_OPTIONS.find((o) => o.value === value.main_cia_risk) ?? null;

  const [frameworkDraft, setFrameworkDraft] = React.useState('');
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

  const removeFramework = (idx) => {
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

      <ColumnLayout columns={2}>
        <FormField
          label="Data sensitivity"
          description="Highest-classification data the application handles."
          errorText={errors.data_sensitivity}
        >
          <Select
            selectedOption={sensitivityOption}
            onChange={({ detail }) =>
              patch({ data_sensitivity: detail.selectedOption.value })
            }
            options={DATA_SENSITIVITY_OPTIONS}
            placeholder="Choose a sensitivity level"
          />
        </FormField>

        <FormField
          label="Main CIA risk"
          description="Which pillar of CIA would hurt the most if compromised."
          errorText={errors.main_cia_risk}
        >
          <Select
            selectedOption={ciaOption}
            onChange={({ detail }) =>
              patch({ main_cia_risk: detail.selectedOption.value })
            }
            options={MAIN_CIA_RISK_OPTIONS}
            placeholder="Choose a risk pillar"
          />
        </FormField>
      </ColumnLayout>
    </SpaceBetween>
  );
}

/**
 * Return an empty BusinessContext — useful for seeding page state before the
 * user has typed anything. Matches the required-field contract: all fields
 * are present but empty, so the form doesn't crash on undefined access.
 */
export function emptyBusinessContext() {
  return {
    description: '',
    regulatory_frameworks: [],
    data_sensitivity: '',
    main_cia_risk: '',
  };
}

/**
 * Validate a BusinessContext. Returns an errors object keyed by field — empty
 * when the context is valid. All four fields are required.
 */
export function validateBusinessContext(ctx) {
  const errors = {};
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
  if (!ctx.main_cia_risk) {
    errors.main_cia_risk = 'Choose the main CIA risk.';
  }
  return errors;
}
