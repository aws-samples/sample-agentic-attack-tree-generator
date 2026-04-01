import { useState } from 'react';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Button from '@cloudscape-design/components/button';
import Input from '@cloudscape-design/components/input';
import TokenGroup from '@cloudscape-design/components/token-group';
import FormField from '@cloudscape-design/components/form-field';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';

function toTokens(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    return value.split(/,\s*/).filter(Boolean);
  }
  return [];
}

function TokenField({ label, items, setItems, placeholder }) {
  const [draft, setDraft] = useState('');

  function add() {
    const trimmed = draft.trim();
    if (!trimmed) return;
    setItems((prev) => [...prev, trimmed]);
    setDraft('');
  }

  return (
    <FormField label={label}>
      {items.length > 0 && (
        <div style={{ marginBottom: 4 }}>
          <TokenGroup
            items={items.map((s) => ({ label: s, dismissLabel: `Remove ${s}` }))}
            onDismiss={({ detail }) =>
              setItems((prev) => prev.filter((_, i) => i !== detail.itemIndex))
            }
          />
        </div>
      )}
      <div style={{ display: 'flex', gap: '8px' }}>
        <div style={{ flex: 1 }}>
          <Input
            value={draft}
            onChange={({ detail }) => setDraft(detail.value)}
            onKeyDown={(e) => { if (e.detail.key === 'Enter') { e.preventDefault(); add(); } }}
            placeholder={placeholder}
          />
        </div>
        <Button variant="icon" iconName="add-plus" onClick={add} ariaLabel={`Add ${label}`} />
      </div>
    </FormField>
  );
}

/** Inline badge list for the read-only summary row. */
export function BadgeList({ items }) {
  if (!items || items.length === 0) return <span style={{ color: '#5f6b7a' }}>&mdash;</span>;
  return (
    <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: '4px' }}>
      {items.map((item, i) => <Badge key={i} color="blue">{item}</Badge>)}
    </span>
  );
}

/**
 * ScannerReviewEditModal — modal form for editing scanner findings.
 */
export default function ScannerReviewEditModal({ visible, scannerData = {}, onSubmit, onDismiss }) {
  const [industry, setIndustry] = useState(scannerData.industry || '');
  const [dataSensitivity, setDataSensitivity] = useState(scannerData.data_sensitivity || '');
  const [cloudProviders, setCloudProviders] = useState(toTokens(scannerData.cloud_provider));
  const [techStack, setTechStack] = useState(toTokens(scannerData.tech_stack));
  const [services, setServices] = useState(scannerData.services || []);
  const [authMechanisms, setAuthMechanisms] = useState(scannerData.auth_mechanisms || []);
  const [compliance, setCompliance] = useState(scannerData.compliance_requirements || []);
  const [submitting, setSubmitting] = useState(false);

  function handleSave() {
    setSubmitting(true);
    onSubmit({
      industry,
      data_sensitivity: dataSensitivity,
      cloud_provider: cloudProviders.join(', '),
      tech_stack: techStack.join(', '),
      services,
      auth_mechanisms: authMechanisms,
      compliance_requirements: compliance,
    });
  }

  return (
    <Modal
      visible={visible}
      onDismiss={onDismiss}
      header="Edit scanner findings"
      size="large"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="link" onClick={onDismiss} disabled={submitting}>Cancel</Button>
            <Button variant="primary" onClick={handleSave} loading={submitting} disabled={submitting}>
              Save & continue
            </Button>
          </SpaceBetween>
        </Box>
      }
    >
      <SpaceBetween size="m">
        <ColumnLayout columns={2} variant="text-grid">
          <TokenField label="Cloud providers" items={cloudProviders} setItems={setCloudProviders} placeholder="e.g. AWS" />
          <TokenField label="Tech stack" items={techStack} setItems={setTechStack} placeholder="e.g. Python" />
        </ColumnLayout>
        <ColumnLayout columns={2} variant="text-grid">
          <FormField label="Industry">
            <Input value={industry} onChange={({ detail }) => setIndustry(detail.value)} placeholder="e.g. healthcare, fintech" />
          </FormField>
          <FormField label="Data sensitivity">
            <Input value={dataSensitivity} onChange={({ detail }) => setDataSensitivity(detail.value)} placeholder="e.g. PII, PHI, financial" />
          </FormField>
        </ColumnLayout>
        <TokenField label="Services & components" items={services} setItems={setServices} placeholder="Add a service" />
        <ColumnLayout columns={2} variant="text-grid">
          <TokenField label="Auth mechanisms" items={authMechanisms} setItems={setAuthMechanisms} placeholder="e.g. IAM roles" />
          <TokenField label="Compliance requirements" items={compliance} setItems={setCompliance} placeholder="e.g. SOC2" />
        </ColumnLayout>
      </SpaceBetween>
    </Modal>
  );
}
