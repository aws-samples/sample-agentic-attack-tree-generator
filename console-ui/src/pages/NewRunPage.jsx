import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
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
import Badge from '@cloudscape-design/components/badge';
import { getApplication, getConfig, getFrameworks, createRun } from '../api-client';
import DirectoryPicker from '../components/DirectoryPicker';

/**
 * NewRunPage — launches a threat model run.
 *
 * In the v2 UX this page is always scoped to an existing Application via
 * the ``/applications/:appId/runs/new`` route:
 *
 *   - project_path is locked to the application's stored path (read-only).
 *   - regulatory_frameworks from the application's business context are
 *     surfaced as pre-selected in the Threat Frameworks step.
 *   - The submission carries ``app_id`` so the run links back to the app.
 *
 * The legacy ``/new-run`` route still works for backwards compatibility
 * (no app scope — user types a path manually) until the v1 flow is
 * retired.
 */
export default function NewRunPage() {
  const navigate = useNavigate();
  const { appId } = useParams();
  const isAppScoped = Boolean(appId);

  const [activeStepIndex, setActiveStepIndex] = useState(0);
  const [projectPath, setProjectPath] = useState('');
  const [threatSource, setThreatSource] = useState('auto');
  const [threatFilePath, setThreatFilePath] = useState('');
  const [config, setConfig] = useState(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [submitError, setSubmitError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // App scope state
  const [app, setApp] = useState(null);
  const [appLoading, setAppLoading] = useState(isAppScoped);
  const [appError, setAppError] = useState('');

  // Framework selection state
  const [availableFrameworks, setAvailableFrameworks] = useState({});
  const [selectedFrameworks, setSelectedFrameworks] = useState({});
  // Ensures we only apply the business-context preselection once the two
  // independent fetches (app + frameworks) have both landed.
  const [frameworksInitialized, setFrameworksInitialized] = useState(false);

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
        if (cancelled || !data.frameworks) return;
        setAvailableFrameworks(data.frameworks);
      })
      .catch(() => {});

    if (isAppScoped) {
      getApplication(appId)
        .then((data) => {
          if (cancelled) return;
          setApp(data);
          if (data.project_path) setProjectPath(data.project_path);
        })
        .catch((err) => {
          if (!cancelled) setAppError(err.message || 'Failed to load application.');
        })
        .finally(() => {
          if (!cancelled) setAppLoading(false);
        });
    }

    return () => { cancelled = true; };
  }, [appId, isAppScoped]);

  /*
   * Preselection rule:
   *   - In app-scoped mode, any framework whose key *or* display name matches
   *     an entry in ``app.business_context.regulatory_frameworks`` starts
   *     checked; everything else starts unchecked.
   *   - Otherwise all frameworks are checked by default (legacy behaviour).
   * The match is case-insensitive so users who type "soc2" or "SOC 2" in
   * business context still get an intuitive result.
   */
  useEffect(() => {
    if (frameworksInitialized) return;
    const keys = Object.keys(availableFrameworks);
    if (keys.length === 0) return;
    if (isAppScoped && !app) return; // wait for app to land

    const preferred = new Set(
      (app?.business_context?.regulatory_frameworks || []).map((f) =>
        String(f).trim().toLowerCase()
      )
    );

    const initial = {};
    for (const key of keys) {
      const name = availableFrameworks[key]?.name || key;
      if (isAppScoped && preferred.size > 0) {
        initial[key] =
          preferred.has(key.toLowerCase()) || preferred.has(name.toLowerCase());
      } else {
        initial[key] = true;
      }
    }
    setSelectedFrameworks(initial);
    setFrameworksInitialized(true);
  }, [availableFrameworks, app, isAppScoped, frameworksInitialized]);

  const validateStep = (stepIndex) => {
    if (stepIndex === 0) {
      // In app-scoped mode the project path is locked and already valid.
      if (isAppScoped) return true;
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
      if (isAppScoped) {
        params.app_id = appId;
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

  const appRegulatory = app?.business_context?.regulatory_frameworks || [];

  const steps = [
    {
      title: 'Project Path',
      content: (
        <Container header={<Header variant="h2">Project Path</Header>}>
          {isAppScoped ? (
            <SpaceBetween size="m">
              {appError && <Alert type="error">{appError}</Alert>}
              <FormField
                label="Project directory path"
                description="Locked to the path registered when the application was created. Edit from the application overview (only available before the first run)."
              >
                <Input value={projectPath} disabled readOnly />
              </FormField>
              {appRegulatory.length > 0 && (
                <Box variant="small" color="text-body-secondary">
                  Regulatory frameworks from this app's business context:{' '}
                  {appRegulatory.map((f, i) => (
                    <Badge key={i} color="blue">
                      {f}
                    </Badge>
                  ))}
                </Box>
              )}
            </SpaceBetween>
          ) : (
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
          )}
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
              {isAppScoped && appRegulatory.length > 0
                ? "Frameworks declared in this application's business context are pre-selected. You can still adjust the selection for this run."
                : 'Select which knowledge bases to map attack steps against. All frameworks are selected by default.'}
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
                {isAppScoped && (
                  <div>
                    <Box variant="awsui-key-label">Application</Box>
                    <div>{app?.name || appId}</div>
                  </div>
                )}
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

  const breadcrumbs = isAppScoped
    ? [
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: app?.name || appId, href: `/applications/${appId}` },
        { text: 'New run', href: `/applications/${appId}/runs/new` },
      ]
    : [
        { text: 'Home', href: '/' },
        { text: 'New Run', href: '/new-run' },
      ];

  if (isAppScoped && appLoading) {
    return (
      <CloudscapeShell activePage={isAppScoped ? '/applications' : '/new-run'} breadcrumbs={breadcrumbs}>
        <Box textAlign="center" padding="l" data-testid="loading-spinner">
          <Spinner size="large" />
        </Box>
      </CloudscapeShell>
    );
  }

  return (
    <CloudscapeShell
      activePage={isAppScoped ? '/applications' : '/new-run'}
      breadcrumbs={breadcrumbs}
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
        onCancel={() =>
          navigate(isAppScoped ? `/applications/${appId}` : '/')
        }
        isLoadingNextStep={submitting}
      />
    </CloudscapeShell>
  );
}
