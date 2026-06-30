'use client';

import { useState } from 'react';
import Modal from '@cloudscape-design/components/modal';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Checkbox from '@cloudscape-design/components/checkbox';
import RadioGroup from '@cloudscape-design/components/radio-group';
import FormField from '@cloudscape-design/components/form-field';
import Alert from '@cloudscape-design/components/alert';
import { DEFAULT_SECTIONS, type ExportSections } from '@/utils/export-service';

/** Output format the modal hands back to its parent. */
export type ExportFormat = 'pdf' | 'csv';

/** Payload passed to {@link CustomiseExportModalProps.onConfirm}. */
export interface CustomiseExportConfirm {
  sections: ExportSections;
  format: ExportFormat;
}

export interface CustomiseExportModalProps {
  visible: boolean;
  onDismiss: () => void;
  onConfirm: (payload: CustomiseExportConfirm) => void;
  loading?: boolean;
  error?: string | null;
  threatCount?: number;
}

/**
 * Single modal that drives every section-customisable export.
 *
 * Replaces the old "Export All / Threats with steps / Threats only /
 * Mitigations" submenu sprawl. The user picks which sections to include
 * and a single format; the parent runs the actual export.
 *
 * ``onConfirm({ sections, format })`` is called when the user clicks
 * Download. The parent owns the loading state — the modal stays mounted
 * with the Download button in ``loading`` while the parent generates the
 * file, then the parent closes the modal by setting ``visible={false}``.
 *
 * Defaults intentionally exclude attack steps; that single flip is the
 * largest contributor to the previous report bloat.
 */
export default function CustomiseExportModal({
  visible,
  onDismiss,
  onConfirm,
  loading = false,
  error = null,
  threatCount = 0,
}: CustomiseExportModalProps) {
  const [sections, setSections] = useState<ExportSections>(DEFAULT_SECTIONS);
  const [format, setFormat] = useState<ExportFormat>('pdf');

  const setSection = (key: keyof ExportSections, checked: boolean) =>
    setSections((prev) => ({ ...prev, [key]: checked }));

  const anySelected = Object.values(sections).some(Boolean);

  const handleConfirm = () => {
    if (!anySelected) return;
    onConfirm({ sections, format });
  };

  return (
    <Modal
      visible={visible}
      onDismiss={() => !loading && onDismiss()}
      header="Customise export"
      size="medium"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onDismiss} disabled={loading}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleConfirm}
              loading={loading}
              disabled={!anySelected}
              data-testid="confirm-customise-export"
            >
              Download
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      <SpaceBetween size="m">
        {error && (
          <Alert type="error" header="Export failed">
            {error}
          </Alert>
        )}

        <FormField
          label="Sections"
          description="Pick what to include. At least one section is required."
          errorText={!anySelected ? 'Select at least one section.' : ''}
        >
          <SpaceBetween size="xs">
            <Checkbox
              checked={sections.threats}
              onChange={({ detail }) => setSection('threats', detail.checked)}
              data-testid="section-threats"
            >
              Threats overview
            </Checkbox>
            <Checkbox
              checked={sections.attackSteps}
              onChange={({ detail }) => setSection('attackSteps', detail.checked)}
              description={
                threatCount > 0
                  ? `Adds ~1 page per threat (${threatCount} threats → roughly ${threatCount} extra pages).`
                  : 'Adds ~1 page per threat.'
              }
              data-testid="section-attack-steps"
            >
              Attack steps
            </Checkbox>
            <Checkbox
              checked={sections.ttp}
              onChange={({ detail }) => setSection('ttp', detail.checked)}
              data-testid="section-ttp"
            >
              TTP mappings
            </Checkbox>
            <Checkbox
              checked={sections.mitigations}
              onChange={({ detail }) => setSection('mitigations', detail.checked)}
              data-testid="section-mitigations"
            >
              Mitigations
            </Checkbox>
          </SpaceBetween>
        </FormField>

        <FormField
          label="Format"
          description={
            format === 'csv'
              ? 'Multiple sections produce a .zip with one CSV each.'
              : 'Single combined PDF with the chosen sections.'
          }
        >
          <RadioGroup
            value={format}
            onChange={({ detail }) => setFormat(detail.value as ExportFormat)}
            items={[
              { value: 'pdf', label: 'PDF' },
              { value: 'csv', label: 'CSV' },
            ]}
            data-testid="format-radio"
          />
        </FormField>
      </SpaceBetween>
    </Modal>
  );
}
