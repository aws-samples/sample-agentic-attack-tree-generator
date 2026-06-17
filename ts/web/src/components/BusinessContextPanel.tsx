'use client';

import { useState } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Button from '@cloudscape-design/components/button';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import type { Application, BusinessContext } from '@threatforest/types';
import BusinessContextForm, {
  DATA_SENSITIVITY_OPTIONS,
  emptyBusinessContext,
  normaliseCiaPriority,
  validateBusinessContext,
  type BusinessContextDraft,
} from './BusinessContextForm';
import { updateApplication } from '@/api/client';

export interface BusinessContextPanelProps {
  appId: string;
  businessContext?: BusinessContext | null;
  onUpdated?: (updated: Application) => void;
  /**
   * Hides the Edit button — used for imported applications that have no v2
   * record on this server, so a PATCH would 404.
   */
  readOnly?: boolean;
}

/**
 * Read-only card showing an application's business context with an "Edit"
 * button that swaps into a modal form. On save, PATCHes the application via
 * the v2 API and calls ``onUpdated(updatedApp)`` so the parent can refresh
 * derived state (header name, etc.).
 *
 * Kept visually identical in structure to the Review step of the create
 * wizard so users see the same layout wherever context is surfaced.
 */
export default function BusinessContextPanel({
  appId,
  businessContext,
  onUpdated,
  readOnly = false,
}: BusinessContextPanelProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<BusinessContextDraft>(
    () => businessContext ?? emptyBusinessContext(),
  );
  const [errors, setErrors] = useState<
    Partial<Record<keyof BusinessContextDraft, string>>
  >({});
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  const ctx: BusinessContextDraft = businessContext ?? emptyBusinessContext();

  const labelFor = (
    value: string,
    options: ReadonlyArray<{ value: string; label: string }>,
  ) => options.find((o) => o.value === value)?.label || value || '—';

  const openEdit = () => {
    // Clone so Cancel discards in-flight edits cleanly.
    setDraft(
      businessContext
        ? {
            ...businessContext,
            regulatory_frameworks: [...(businessContext.regulatory_frameworks || [])],
          }
        : emptyBusinessContext(),
    );
    setErrors({});
    setSubmitError('');
    setEditing(true);
  };

  const closeEdit = () => {
    setEditing(false);
  };

  const handleSave = async () => {
    const validationErrors = validateBusinessContext(draft);
    setErrors(validationErrors);
    if (Object.keys(validationErrors).length > 0) return;

    setSubmitting(true);
    setSubmitError('');
    try {
      // Validation above guarantees data_sensitivity is a real enum value.
      const updated = await updateApplication(appId, {
        businessContext: draft as BusinessContext,
      });
      if (onUpdated) onUpdated(updated);
      setEditing(false);
    } catch (err) {
      setSubmitError(
        (err instanceof Error && err.message) || 'Failed to update business context.',
      );
    } finally {
      setSubmitting(false);
    }
  };

  const frameworks = ctx.regulatory_frameworks || [];

  return (
    <Container
      header={
        <Header
          variant="h2"
          actions={
            readOnly ? undefined : (
              <Button
                iconName="edit"
                onClick={openEdit}
                data-testid="edit-business-context"
              >
                Edit
              </Button>
            )
          }
        >
          Business context
        </Header>
      }
    >
      <SpaceBetween size="m">
        <ColumnLayout columns={2} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">Description</Box>
            <div>{ctx.description || '—'}</div>
          </div>
          <div>
            <Box variant="awsui-key-label">Regulatory frameworks</Box>
            {frameworks.length > 0 ? (
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                {frameworks.map((f, i) => (
                  <Badge key={i} color="blue">
                    {f}
                  </Badge>
                ))}
              </div>
            ) : (
              <div>—</div>
            )}
          </div>
          <div>
            <Box variant="awsui-key-label">Data sensitivity</Box>
            <div>{labelFor(ctx.data_sensitivity, DATA_SENSITIVITY_OPTIONS)}</div>
          </div>
          <div>
            <Box variant="awsui-key-label">CIA priority</Box>
            <ol style={{ margin: 0, paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 2 }}>
              {normaliseCiaPriority(ctx.cia_priority).map((v) => (
                <li key={v} style={{ textTransform: 'capitalize' }}>{v}</li>
              ))}
            </ol>
          </div>
        </ColumnLayout>
      </SpaceBetween>

      <Modal
        visible={editing}
        onDismiss={closeEdit}
        header="Edit business context"
        size="large"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={closeEdit} disabled={submitting}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={handleSave}
                loading={submitting}
                data-testid="save-business-context"
              >
                Save
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="l">
          {submitError && (
            <Alert type="error" dismissible onDismiss={() => setSubmitError('')}>
              {submitError}
            </Alert>
          )}
          <BusinessContextForm
            value={draft}
            onChange={(next) => {
              setDraft(next);
              // Clear field errors as the user fills them in.
              setErrors((prev) => {
                const cleared = { ...prev };
                for (const key of Object.keys(cleared) as Array<keyof BusinessContextDraft>) {
                  const current = next[key];
                  if (Array.isArray(current) ? current.length : current) {
                    delete cleared[key];
                  }
                }
                return cleared;
              });
            }}
            errors={errors}
          />
        </SpaceBetween>
      </Modal>
    </Container>
  );
}
