import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import CloudscapeShell from '../components/CloudscapeShell';
import Wizard from '@cloudscape-design/components/wizard';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import RadioGroup from '@cloudscape-design/components/radio-group';
import Checkbox from '@cloudscape-design/components/checkbox';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Spinner from '@cloudscape-design/components/spinner';
import { getConfig, getFrameworks, createRun } from '../api-client';
import DirectoryPicker from '../components/DirectoryPicker';

export default function NewRunPage() {
  const navigate = useNavigate();

  const [activeStepIndex, setActiveStepIndex] = useState(0);
  const [projectPath, setProjectPath] = useState('');
  const [threatSource, setThreatSource] = useState('auto');
  const [threatFilePath, setThreatFilePath] = useState('');
  const [config, setConfig] = useState(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [submitError, setSubmitError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Framework selection state
  const [availableFrameworks, setAvailableFrameworks] = useState({});
  const [selectedFrameworks, setSelectedFrameworks] = useState({});

  // Validation error states
  const [projectPathError, setProjectPathError] = useState('');
  const [threatFilePathError, setThreatFilePathError] = useState('');
  const [frameworkError, setFrameworkError] = useState('');

  useEffect(() => {
    let cancelled = false;
    getConfig()
      .then((data) => { if (!cancelled) setConfig(data); })
      .catch(() => { if (!cancelled) setConfig(null); })
      .finally(() => { if (!cancelled) setConfigLoading(false); });

    getFrameworks()
      .then((data) => {
        if (!cancelled && data.frameworks) {
          setAvailableFrameworks(data.frameworks);
          // Default: all checked
          const initial = {};
          for (const key of Object.keys(data.frameworks)) {
            initial[key] = true;
          }
          setSelectedFrameworks(initial);
        }
      })
      .catch(() => {});

    return () => { cancelled = true; };
  }, []);

  const validateStep = (stepIndex) => {
    if (stepIndex === 0) {
      if (!projectPath.trim()) {
        setProjectPathError('Project path is required.');
        return false;
      }
      setProjectPathError('');
      return true;
    }
    if (stepIndex === 1) {
      if (threatSource === 'file' && !threatFilePath.trim()) {
        setThreatFilePathError('Threat file path is required when using a file source.');
        return false;
      }
      setThreatFilePathError('');
      return true;
    }
    if (stepIndex === 2) {
      const anySelected = Object.values(selectedFrameworks).some(Boolean);
      if (!anySelected) {
        setFrameworkError('Select at least one framework.');
        return false;
      }
      setFrameworkError('');
      return true;
    }
    return true;
  };

  const handleNavigate = (event) => {
    const { requestedStepIndex, reason } = event.detail;
    if (reason === 'next') {
      if (!validateStep(activeStepIndex)) return;
    }
    setActiveStepIndex(requestedStepIndex);
  };

  const handleSubmit = async () => {
    setSubmitError('');
    setSubmitting(true);
    try {
      const chosenFrameworks = Object.entries(selectedFrameworks)
        .filter(([, checked]) => checked)
        .map(([key]) => key);

      const params = {
        project_path: projectPath,
        threat_source: threatSource,
        frameworks: chosenFrameworks,
      };
      if (threatSource === 'file') {
        params.threat_file_path = threatFilePath;
      }
      const result = await createRun(params);
      navigate(`/runs/${result.run_id}/progress`);
    } catch (err) {
      setSubmitError(err.message || 'Failed to create run.');
    } finally {
      setSubmitting(false);
    }
  };

  const frameworkKeys = Object.keys(availableFrameworks);
  const selectedNames = Object.entries(selectedFrameworks)
    .filter(([, checked]) => checked)
    .map(([key]) => availableFrameworks[key]?.name || key);

  const steps = [
    {
      title: 'Project Path',
      content: (
        <Container header={<Header variant="h2">Project Path</Header>}>
          <FormField
            label="Project directory path"
            errorText={projectPathError}
            description="Enter the path or browse to the project directory to analyze."
          >
            <DirectoryPicker
              value={projectPath}
              onChange={(val) => {
                setProjectPath(val);
                if (val.trim()) setProjectPathError('');
              }}
              placeholder="/path/to/project"
            />
          </FormField>
        </Container>
      ),
    },
    {
      title: 'Threat Statements',
      content: (
        <Container header={<Header variant="h2">Threat Statements</Header>}>
          <SpaceBetween size="l">
            <FormField label="Threat source">
              <RadioGroup
                value={threatSource}
                onChange={({ detail }) => {
                  setThreatSource(detail.value);
                  if (detail.value === 'auto') setThreatFilePathError('');
                }}
                items={[
                  { value: 'auto', label: 'Auto-generate using AI' },
                  { value: 'file', label: 'Provide existing threat statements file' },
                ]}
              />
            </FormField>
            {threatSource === 'file' && (
              <FormField
                label="Threat file path"
                errorText={threatFilePathError}
                description="Enter the path to the threat statements file."
              >
                <Input
                  value={threatFilePath}
                  onChange={({ detail }) => {
                    setThreatFilePath(detail.value);
                    if (detail.value.trim()) setThreatFilePathError('');
                  }}
                  placeholder="/path/to/threats.json"
                />
              </FormField>
            )}
          </SpaceBetween>
        </Container>
      ),
    },
    {
      title: 'Threat Frameworks',
      content: (
        <Container header={<Header variant="h2">Threat Frameworks</Header>}>
          <SpaceBetween size="l">
            <Box variant="p" color="text-body-secondary">
              Select which knowledge bases to map attack steps against. All frameworks are selected by default.
            </Box>
            {frameworkError && (
              <Alert type="error" dismissible onDismiss={() => setFrameworkError('')}>
                {frameworkError}
              </Alert>
            )}
            <FormField label="Frameworks">
              <SpaceBetween size="xs">
                {frameworkKeys.map((key) => (
                  <Checkbox
                    key={key}
                    checked={!!selectedFrameworks[key]}
                    onChange={({ detail }) => {
                      setSelectedFrameworks((prev) => ({ ...prev, [key]: detail.checked }));
                      setFrameworkError('');
                    }}
                  >
                    <Box variant="strong">{availableFrameworks[key].name}</Box>
                    {' '}
                    <Box variant="small" color="text-body-secondary" display="inline">
                      — {availableFrameworks[key].description}
                    </Box>
                  </Checkbox>
                ))}
              </SpaceBetween>
            </FormField>
          </SpaceBetween>
        </Container>
      ),
    },
    {
      title: 'Review & Confirm',
      content: (
        <Container header={<Header variant="h2">Review & Confirm</Header>}>
          <SpaceBetween size="l">
            {submitError && (
              <Alert type="error" dismissible onDismiss={() => setSubmitError('')}>
                {submitError}
              </Alert>
            )}
            {configLoading ? (
              <Box textAlign="center" padding="l">
                <Spinner size="large" />
              </Box>
            ) : (
              <ColumnLayout columns={2} variant="text-grid">
                <div>
                  <Box variant="awsui-key-label">Project path</Box>
                  <div>{projectPath}</div>
                </div>
                <div>
                  <Box variant="awsui-key-label">Threat source</Box>
                  <div>{threatSource === 'auto' ? 'Auto-generate using AI' : 'File'}</div>
                </div>
                {threatSource === 'file' && (
                  <div>
                    <Box variant="awsui-key-label">Threat file path</Box>
                    <div>{threatFilePath}</div>
                  </div>
                )}
                <div>
                  <Box variant="awsui-key-label">Frameworks</Box>
                  <div>{selectedNames.join(', ') || 'None selected'}</div>
                </div>
                <div>
                  <Box variant="awsui-key-label">Model provider</Box>
                  <div>{config?.model_provider || '—'}</div>
                </div>
                <div>
                  <Box variant="awsui-key-label">Model ID</Box>
                  <div>{config?.model_id || '—'}</div>
                </div>
              </ColumnLayout>
            )}
          </SpaceBetween>
        </Container>
      ),
    },
  ];

  return (
    <CloudscapeShell
      activePage="/new-run"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'New Run', href: '/new-run' },
      ]}
    >
      <Wizard
        i18nStrings={{
          stepNumberLabel: (stepNumber) => `Step ${stepNumber}`,
          collapsedStepsLabel: (stepNumber, stepsCount) =>
            `Step ${stepNumber} of ${stepsCount}`,
          submitButton: 'Submit',
          previousButton: 'Previous',
          nextButton: 'Next',
          cancelButton: 'Cancel',
          optional: 'optional',
        }}
        steps={steps}
        activeStepIndex={activeStepIndex}
        onNavigate={handleNavigate}
        onSubmit={handleSubmit}
        onCancel={() => navigate('/')}
        isLoadingNextStep={submitting}
      />
    </CloudscapeShell>
  );
}
