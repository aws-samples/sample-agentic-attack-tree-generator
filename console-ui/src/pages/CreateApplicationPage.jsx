import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Wizard from '@cloudscape-design/components/wizard';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import CloudscapeShell from '../components/CloudscapeShell';
import DirectoryPicker from '../components/DirectoryPicker';
import BusinessContextForm, {
  DATA_SENSITIVITY_OPTIONS,
  MAIN_CIA_RISK_OPTIONS,
  emptyBusinessContext,
  validateBusinessContext,
} from '../components/BusinessContextForm';
import { createApplication } from '../api-client';

/**
 * Entry point for the v2 application-as-container UX.
 *
 * A 3-step wizard:
 *   1. Identity   — user-chosen name (unique, case-insensitive) + project path
 *   2. Business   — required BusinessContext seeded into the scanner
 *   3. Review     — read-only confirmation before creating the record
 *
 * On success we navigate to the new AppOverviewPage; the "start a run" step
 * happens from there so the overview page is always the canonical home for
 * an application.
 */
export default function CreateApplicationPage() {
  const navigate = useNavigate();

  const [activeStepIndex, setActiveStepIndex] = useState(0);

  // Step 1 — identity
  const [name, setName] = useState('');
  const [projectPath, setProjectPath] = useState('');
  const [nameError, setNameError] = useState('');
  const [pathError, setPathError] = useState('');

  // Step 2 — business context
  const [businessContext, setBusinessContext] = useState(emptyBusinessContext());
  const [contextErrors, setContextErrors] = useState({});

  // Submission
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  const labelFor = (value, options) =>
    options.find((o) => o.value === value)?.label || value || '—';

  const validateStep = (stepIndex) => {
    if (stepIndex === 0) {
      let ok = true;
      if (!name.trim()) {
        setNameError('Application name is required.');
        ok = false;
      } else {
        setNameError('');
      }
      if (!projectPath.trim()) {
        setPathError('Project path is required.');
        ok = false;
      } else {
        setPathError('');
      }
      return ok;
    }
    if (stepIndex === 1) {
      const errors = validateBusinessContext(businessContext);
      setContextErrors(errors);
      return Object.keys(errors).length === 0;
    }
    return true;
  };

  const handleNavigate = (event) => {
    const { requestedStepIndex, reason } = event.detail;
    if (reason === 'next' && !validateStep(activeStepIndex)) return;
    setActiveStepIndex(requestedStepIndex);
  };

  const handleSubmit = async () => {
    // Final defence — the wizard already validated each step, but the user
    // could still have backtracked and left something invalid.
    for (const idx of [0, 1]) {
      if (!validateStep(idx)) {
        setActiveStepIndex(idx);
        return;
      }
    }

    setSubmitting(true);
    setSubmitError('');
    try {
      const app = await createApplication({
        name: name.trim(),
        projectPath: projectPath.trim(),
        businessContext,
      });
      navigate(`/applications/${app.id}`);
    } catch (err) {
      // 409 bubbles up as the repository's error message — usually enough
      // for the user to reconcile. Steer them back to the right step.
      setSubmitError(err.message || 'Failed to create application.');
      if (/name/i.test(err.message || '')) {
        setActiveStepIndex(0);
        setNameError(err.message);
      } else if (/project_path|path/i.test(err.message || '')) {
        setActiveStepIndex(0);
        setPathError(err.message);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const steps = [
    {
      title: 'Identity',
      description:
        'Name this application and point ThreatForest at the repository it should analyse.',
      content: (
        <Container header={<Header variant="h2">Identity</Header>}>
          <SpaceBetween size="l">
            <FormField
              label="Application name"
              description="Displayed throughout the console. Case-insensitively unique across all applications."
              errorText={nameError}
            >
              <Input
                value={name}
                onChange={({ detail }) => {
                  setName(detail.value);
                  if (detail.value.trim()) setNameError('');
                }}
                placeholder="e.g. Payments API"
              />
            </FormField>

            <FormField
              label="Project path"
              description="The repository folder that will be scanned when you start a run."
              errorText={pathError}
            >
              <DirectoryPicker
                value={projectPath}
                onChange={(val) => {
                  setProjectPath(val);
                  if (val.trim()) setPathError('');
                }}
                placeholder="/path/to/repo"
              />
            </FormField>
          </SpaceBetween>
        </Container>
      ),
    },
    {
      title: 'Business context',
      description:
        'These fields seed the scanner and downstream agents. Treat as authoritative — the scanner will not overwrite them.',
      content: (
        <Container header={<Header variant="h2">Business context</Header>}>
          <BusinessContextForm
            value={businessContext}
            onChange={(next) => {
              setBusinessContext(next);
              // Clear field-level errors as the user edits them.
              setContextErrors((prev) => {
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
            errors={contextErrors}
          />
        </Container>
      ),
    },
    {
      title: 'Review & create',
      description: 'Confirm the details below — you can edit everything later from the app overview.',
      content: (
        <Container header={<Header variant="h2">Review & create</Header>}>
          <SpaceBetween size="l">
            {submitError && (
              <Alert type="error" dismissible onDismiss={() => setSubmitError('')}>
                {submitError}
              </Alert>
            )}
            <ColumnLayout columns={2} variant="text-grid">
              <div>
                <Box variant="awsui-key-label">Name</Box>
                <div>{name || '—'}</div>
              </div>
              <div>
                <Box variant="awsui-key-label">Project path</Box>
                <div>{projectPath || '—'}</div>
              </div>
              <div>
                <Box variant="awsui-key-label">Data sensitivity</Box>
                <div>{labelFor(businessContext.data_sensitivity, DATA_SENSITIVITY_OPTIONS)}</div>
              </div>
              <div>
                <Box variant="awsui-key-label">Main CIA risk</Box>
                <div>{labelFor(businessContext.main_cia_risk, MAIN_CIA_RISK_OPTIONS)}</div>
              </div>
              <div>
                <Box variant="awsui-key-label">Regulatory frameworks</Box>
                <div>
                  {businessContext.regulatory_frameworks?.length
                    ? businessContext.regulatory_frameworks.join(', ')
                    : '—'}
                </div>
              </div>
              <div>
                <Box variant="awsui-key-label">Description</Box>
                <div>{businessContext.description || '—'}</div>
              </div>
            </ColumnLayout>
          </SpaceBetween>
        </Container>
      ),
    },
  ];

  return (
    <CloudscapeShell
      activePage="/applications/new"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: 'New application', href: '/applications/new' },
      ]}
    >
      <Wizard
        i18nStrings={{
          stepNumberLabel: (stepNumber) => `Step ${stepNumber}`,
          collapsedStepsLabel: (stepNumber, stepsCount) =>
            `Step ${stepNumber} of ${stepsCount}`,
          submitButton: 'Create application',
          previousButton: 'Previous',
          nextButton: 'Next',
          cancelButton: 'Cancel',
          optional: 'optional',
        }}
        steps={steps}
        activeStepIndex={activeStepIndex}
        onNavigate={handleNavigate}
        onSubmit={handleSubmit}
        onCancel={() => navigate('/applications')}
        isLoadingNextStep={submitting}
      />
    </CloudscapeShell>
  );
}
