import React, { useState } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Button from '@cloudscape-design/components/button';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import BusinessContextForm, {
  DATA_SENSITIVITY_OPTIONS,
  MAIN_CIA_RISK_OPTIONS,
  emptyBusinessContext,
  validateBusinessContext,
} from './BusinessContextForm';
import { updateApplication } from '../api-client';

/**
 * Read-only card showing an application's business context with an "Edit"
 * button that swaps into a modal form. On save, PATCHes the application via
 * the v2 API and calls ``onUpdated(updatedApp)`` so the parent can refresh
 * derived state (header name, etc.).
 *
 * Kept visually identical in structure to the Review step of the create
 * wizard so users see the same layout wherever context is surfaced.
 */
export default function BusinessContextPanel({ appId, businessContext, onUpdated }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(() => businessContext || emptyBusinessContext());
  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  const ctx = businessContext || emptyBusinessContext();

  const labelFor = (value, options) =>
    options.find((o) => o.value === value)?.label || value || '—';

  const openEdit = () => {
    // Clone so Cancel discards in-flight edits cleanly.
    setDraft(ctx ? { ...ctx, regulatory_frameworks: [...(ctx.regulatory_frameworks || [])] } : emptyBusinessContext());
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
      const updated = await updateApplication(appId, { businessContext: draft });
      if (onUpdated) onUpdated(updated);
      setEditing(false);
    } catch (err) {
      setSubmitError(err.message || 'Failed to update business context.');
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
            <Button
              iconName="edit"
              onClick={openEdit}
              data-testid="edit-business-context"
            >
              Edit
            </Button>
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
            <Box variant="awsui-key-label">Main CIA risk</Box>
            <div>{labelFor(ctx.main_cia_risk, MAIN_CIA_RISK_OPTIONS)}</div>
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
                for (const key of Object.keys(cleared)) {
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
