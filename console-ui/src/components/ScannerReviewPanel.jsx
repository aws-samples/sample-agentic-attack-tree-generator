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

const FIELD_HELP = {
  cloud_provider: 'Cloud platform(s) hosting the application (e.g. AWS, Azure, GCP).',
  tech_stack: 'Primary languages, frameworks, and runtimes used in the codebase.',
  industry: 'Business domain of the application — shapes threat relevance and compliance.',
  services: 'Discrete services, components, or modules that make up the system.',
  auth_mechanisms: 'How users and services authenticate (e.g. IAM roles, OAuth2, API keys).',
  compliance_requirements: 'Regulatory or contractual frameworks the system must meet (e.g. SOC2, HIPAA).',
};

function InfoPopover({ text }) {
  return (
    <span
      title={text}
      aria-label={text}
      role="img"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '14px',
        height: '14px',
        borderRadius: '50%',
        border: '1px solid #5f6b7a',
        color: '#5f6b7a',
        fontSize: '10px',
        fontStyle: 'italic',
        fontFamily: 'serif',
        lineHeight: 1,
        cursor: 'help',
        marginLeft: '4px',
        verticalAlign: 'middle',
      }}
    >
      i
    </span>
  );
}

function toTokens(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    return value.split(/,\s*/).filter(Boolean);
  }
  return [];
}

function TokenField({ label, items, setItems, placeholder, info }) {
  const [draft, setDraft] = useState('');

  function add() {
    const trimmed = draft.trim();
    if (!trimmed) return;
    setItems((prev) => [...prev, trimmed]);
    setDraft('');
  }

  return (
    <FormField label={label} info={info}>
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
          <TokenField
            label="Cloud providers"
            items={cloudProviders}
            setItems={setCloudProviders}
            placeholder="e.g. AWS"
            info={<InfoPopover text={FIELD_HELP.cloud_provider} />}
          />
          <TokenField
            label="Tech stack"
            items={techStack}
            setItems={setTechStack}
            placeholder="e.g. Python"
            info={<InfoPopover text={FIELD_HELP.tech_stack} />}
          />
        </ColumnLayout>
        <ColumnLayout columns={2} variant="text-grid">
          <FormField label="Industry" info={<InfoPopover text={FIELD_HELP.industry} />}>
            <Input value={industry} onChange={({ detail }) => setIndustry(detail.value)} placeholder="e.g. healthcare, fintech" />
          </FormField>
        </ColumnLayout>
        <TokenField
          label="Services & components"
          items={services}
          setItems={setServices}
          placeholder="Add a service"
          info={<InfoPopover text={FIELD_HELP.services} />}
        />
        <ColumnLayout columns={2} variant="text-grid">
          <TokenField
            label="Auth mechanisms"
            items={authMechanisms}
            setItems={setAuthMechanisms}
            placeholder="e.g. IAM roles"
            info={<InfoPopover text={FIELD_HELP.auth_mechanisms} />}
          />
          <TokenField
            label="Compliance requirements"
            items={compliance}
            setItems={setCompliance}
            placeholder="e.g. SOC2"
            info={<InfoPopover text={FIELD_HELP.compliance_requirements} />}
          />
        </ColumnLayout>
      </SpaceBetween>
    </Modal>
  );
}
