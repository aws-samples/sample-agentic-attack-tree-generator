import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import CloudscapeShell from '../components/CloudscapeShell';
import Form from '@cloudscape-design/components/form';
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
import Button from '@cloudscape-design/components/button';
import { getApplication, getConfig, getFrameworks, createRun } from '../api-client';
import DirectoryPicker from '../components/DirectoryPicker';

/**
 * NewRunPage — launches a threat model run.
 *
 * In the v2 UX this page is always scoped to an existing Application via
 * the ``/applications/:appId/runs/new`` route:
 *
 *   - project_path is locked to the application's stored path (read-only).
 *   - All TTP frameworks (MITRE ATT&CK, ATLAS, Wiz Cloud, …) are checked by
 *     default; the user can deselect any before starting the run.
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

  useEffect(() => {
    if (frameworksInitialized) return;
    const keys = Object.keys(availableFrameworks);
    if (keys.length === 0) return;
    if (isAppScoped && !app) return; // wait for app to land

    const initial = {};
    for (const key of keys) {
      initial[key] = true;
    }
    setSelectedFrameworks(initial);
    setFrameworksInitialized(true);
  }, [availableFrameworks, app, isAppScoped, frameworksInitialized]);

  /**
   * Single-page validator — runs all field checks at once on submit and
   * returns true only when every required field is filled. Each failing
   * field surfaces its own inline error via the field-level state, so the
   * user sees every problem in one pass rather than discovering them step
   * by step.
   */
  function validateAll() {
    let ok = true;

    if (!isAppScoped && !projectPath.trim()) {
      setProjectPathError('Project path is required.');
      ok = false;
    } else {
      setProjectPathError('');
    }

    if (threatSource === 'file' && !threatFilePath.trim()) {
      setThreatFilePathError('Threat file path is required when using a file source.');
      ok = false;
    } else {
      setThreatFilePathError('');
    }

    const anySelected = Object.values(selectedFrameworks).some(Boolean);
    if (!anySelected) {
      setFrameworkError('Select at least one framework.');
      ok = false;
    } else {
      setFrameworkError('');
    }

    return ok;
  }

  const handleSubmit = async () => {
    setSubmitError('');
    if (!validateAll()) return;
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

  const breadcrumbs = isAppScoped
    ? [
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: app?.name || appId, href: `/applications/${appId}` },
        { text: 'New threat model', href: `/applications/${appId}/runs/new` },
      ]
    : [
        { text: 'Home', href: '/' },
        { text: 'Applications', href: '/applications' },
        { text: 'New threat model', href: '/new-run' },
      ];

  if (isAppScoped && appLoading) {
    return (
      <CloudscapeShell activePage="/applications" breadcrumbs={breadcrumbs}>
        <Box textAlign="center" padding="l" data-testid="loading-spinner">
          <Spinner size="large" />
        </Box>
      </CloudscapeShell>
    );
  }

  return (
    <CloudscapeShell
      activePage="/applications"
      breadcrumbs={breadcrumbs}
    >
      {/*
        Single-page form. Replaces what used to be a four-step Wizard
        (Project Path → Threat Source → Threat Frameworks → Review).
        The original review step is gone — on a single page the user can
        already see what they typed, so a separate confirm screen was
        unused chrome. Run config (model provider / id) is now a small
        "Run with" panel above the submit button so users still see what
        will execute, without a dedicated step.
      */}
      <Form
        header={
          <Header variant="h1" description="Configure and start a new threat model run.">
            New threat model
          </Header>
        }
        errorText={submitError || undefined}
        actions={
          <SpaceBetween direction="horizontal" size="xs">
            <Button
              variant="link"
              onClick={() =>
                navigate(isAppScoped ? `/applications/${appId}` : '/')
              }
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleSubmit}
              loading={submitting}
              data-testid="start-run"
            >
              Start threat model
            </Button>
          </SpaceBetween>
        }
      >
        <SpaceBetween size="l">
          {isAppScoped && appError && <Alert type="error">{appError}</Alert>}

          <Container header={<Header variant="h2">Project</Header>}>
            <FormField
              label="Project directory path"
              errorText={projectPathError}
              description={
                isAppScoped
                  ? 'Pre-filled from the application record. Edit if the folder has been renamed or moved — the change is saved back to the application.'
                  : 'Enter the path or browse to the project directory to analyze.'
              }
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

          <Container
            header={
              <Header
                variant="h2"
                description="Choose whether ThreatForest should generate threat statements from the repository or use an existing file."
              >
                Threat source
              </Header>
            }
          >
            <SpaceBetween size="m">
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

          <Container
            header={
              <Header
                variant="h2"
                description="Select which knowledge bases to map attack steps against. All frameworks are selected by default."
              >
                Threat frameworks
              </Header>
            }
          >
            <FormField errorText={frameworkError}>
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
          </Container>

          <Container header={<Header variant="h2">Run with</Header>}>
            {configLoading ? (
              <Box textAlign="center" padding="m">
                <Spinner />
              </Box>
            ) : (
              <ColumnLayout columns={2} variant="text-grid">
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
          </Container>
        </SpaceBetween>
      </Form>
    </CloudscapeShell>
  );
}
