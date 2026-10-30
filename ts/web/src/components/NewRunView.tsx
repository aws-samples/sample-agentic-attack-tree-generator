'use client';

/**
 * NewRunView — TS/Next port of console-ui's NewRunPage.jsx.
 *
 * Launches a threat model run. Shared by two routes:
 *   - /applications/:appId/runs/new  (app-scoped — project_path locked to the
 *     application record, submission carries app_id)
 *   - /new-run                       (legacy un-scoped — user types a path)
 *
 * The app-scope is driven entirely by the `appId` param (undefined ⇒ legacy).
 * react-router (useNavigate/useParams) → next/navigation (useRouter/useParams).
 * CloudscapeShell → AppShell.
 */

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useRealParams } from '@/hooks/useRealParams';
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
import FileUpload from '@cloudscape-design/components/file-upload';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import type { BreadcrumbGroupProps } from '@cloudscape-design/components/breadcrumb-group';
import AppShell from '@/components/AppShell';
import DirectoryPicker from '@/components/DirectoryPicker';
import {
  getApplication,
  getApplicationSources,
  type SourceSelection,
  getConfig,
  getFrameworks,
  createRun,
  uploadApplicationArtifact,
  type HostedRunConfig,
} from '@/api/client';
import {
  archiveDirectoryFiles,
  directoryFileKey,
  type DirectoryFile,
} from '@/utils/directory-archive';
import {
  TTP_FRAMEWORK_CATALOG,
  TTP_FRAMEWORK_IDS,
  type Application,
  type ConfigResponse,
  type TtpFrameworkId,
} from '@threatforest/types';

type FrameworkCatalog = Record<
  TtpFrameworkId,
  { name: string; description: string }
>;

function canonicalFrameworkCatalog(
  discovered: Record<string, { name: string; description: string }> = {},
): FrameworkCatalog {
  return Object.fromEntries(
    TTP_FRAMEWORK_IDS.map((id) => [
      id,
      { ...(discovered[id] ?? TTP_FRAMEWORK_CATALOG[id]) },
    ]),
  ) as FrameworkCatalog;
}

export default function NewRunView() {
  const router = useRouter();
  // Mounted at both "/new-run" (no appId) and "/applications/[appId]/runs/new".
  // useRealParams resolves appId from the live pathname under static export;
  // on the unscoped route the segment is absent so appId is ''.
  const params = useRealParams<{ appId: string }>('/applications/[appId]/runs/new');
  const appId = params.appId || undefined;
  const isAppScoped = Boolean(appId);

  const [projectPath, setProjectPath] = useState('');
  const [sourceFiles, setSourceFiles] = useState<File[]>([]);
  const [existingSources, setExistingSources] = useState<SourceSelection[]>([]);
  const [selectedSources, setSelectedSources] = useState<string[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(isAppScoped);
  const [sourcesError, setSourcesError] = useState('');
  const [directoryFiles, setDirectoryFiles] = useState<DirectoryFile[]>([]);
  const [threatSource, setThreatSource] = useState<'auto' | 'file'>('auto');
  const [threatFilePath, setThreatFilePath] = useState('');
  const [threatFile, setThreatFile] = useState<File | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [submitError, setSubmitError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStatus, setUploadStatus] = useState('');
  const directoryInputRef = useRef<HTMLInputElement | null>(null);
  const uploadedArtifactsRef = useRef(new WeakMap<File, string>());
  const directoryArchiveRef = useRef<{
    inputs: readonly DirectoryFile[];
    archive: File;
  } | null>(null);

  // App scope state
  const [app, setApp] = useState<Application | null>(null);
  const [appLoading, setAppLoading] = useState(isAppScoped);
  const [appError, setAppError] = useState('');

  // Framework selection state
  const [availableFrameworks, setAvailableFrameworks] = useState<FrameworkCatalog>(
    canonicalFrameworkCatalog,
  );
  const [selectedFrameworks, setSelectedFrameworks] = useState<Record<string, boolean>>({});
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
      .then((data) => {
        if (!cancelled) setConfig(data);
      })
      .catch(() => {
        if (!cancelled) setConfig(null);
      })
      .finally(() => {
        if (!cancelled) setConfigLoading(false);
      });

    getFrameworks()
      .then((data) => {
        if (cancelled || !data.frameworks) return;
        setAvailableFrameworks(canonicalFrameworkCatalog(data.frameworks));
      })
      .catch(() => {});

    if (isAppScoped && appId) {
      getApplicationSources(appId).then(({ sources }) => {
        if (cancelled) return;
        setExistingSources(sources);
        setSelectedSources(sources.map(source => source.artifact_id));
      }).catch(error => {
        if (!cancelled) setSourcesError(error instanceof Error ? error.message : 'Unable to load sources.');
      }).finally(() => { if (!cancelled) setSourcesLoading(false); });
      getApplication(appId)
        .then((data) => {
          if (cancelled) return;
          setApp(data);
          if (data.project_path) setProjectPath(data.project_path);
        })
        .catch((err) => {
          if (!cancelled) setAppError(err instanceof Error ? err.message : 'Failed to load application.');
        })
        .finally(() => {
          if (!cancelled) setAppLoading(false);
        });
    }

    return () => {
      cancelled = true;
    };
  }, [appId, isAppScoped]);

  useEffect(() => {
    if (frameworksInitialized) return;
    const keys = TTP_FRAMEWORK_IDS;
    if (isAppScoped && !app) return; // wait for app to land

    const initial: Record<string, boolean> = {};
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
  function validateAll(): boolean {
    let ok = true;

    if (isAppScoped && (sourcesLoading || sourcesError)) {
      setProjectPathError('Source selection is unavailable. Reload this page before starting a run.');
      ok = false;
    } else if (isAppScoped && !selectedSources.length && !sourceFiles.length && !directoryFiles.length) {
      setProjectPathError('Select at least one source or upload new project files.');
      ok = false;
    } else if (isAppScoped && sourceFiles.some((file) => file.size === 0)) {
      setProjectPathError(
        'Empty individual files cannot be uploaded. Select their directory instead.',
      );
      ok = false;
    } else if (!isAppScoped && !projectPath.trim()) {
      setProjectPathError('Project path is required.');
      ok = false;
    } else {
      setProjectPathError('');
    }

    if (
      threatSource === 'file' &&
      (isAppScoped ? threatFile === null : !threatFilePath.trim())
    ) {
      setThreatFilePathError(
        isAppScoped
          ? 'Select a threat statements file.'
          : 'Threat file path is required when using a file source.',
      );
      ok = false;
    } else if (isAppScoped && threatSource === 'file' && threatFile?.size === 0) {
      setThreatFilePathError('The threat statements file is empty.');
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

  const handleDirectorySelection = (files: FileList | null) => {
    if (!files) return;
    setDirectoryFiles((current) => {
      const byKey = new Map(current.map((file) => [directoryFileKey(file), file]));
      for (const file of Array.from(files) as DirectoryFile[]) {
        byKey.set(directoryFileKey(file), file);
      }
      return [...byKey.values()];
    });
    setProjectPathError('');
  };

  const handleSubmit = async () => {
    setSubmitError('');
    if (!validateAll()) return;
    setSubmitting(true);
    setUploadProgress(0);
    setUploadStatus('');
    try {
      const chosenFrameworks = Object.entries(selectedFrameworks)
        .filter(([, checked]) => checked)
        .map(([key]) => key);

      let sourceArtifactIds: string[] | undefined;
      let threatArtifactId: string | null | undefined;
      if (isAppScoped && appId) {
        setUploadStatus('Preparing selected project files');
        const projectFiles = [...sourceFiles];
        if (directoryFiles.length > 0) {
          const cachedArchive = directoryArchiveRef.current;
          const archive =
            cachedArchive !== null &&
            cachedArchive.inputs.length === directoryFiles.length &&
            cachedArchive.inputs.every((file, index) => file === directoryFiles[index])
              ? cachedArchive.archive
              : await archiveDirectoryFiles(directoryFiles);
          directoryArchiveRef.current = { inputs: directoryFiles, archive };
          projectFiles.push(archive);
        }
        const filesToUpload = [
          ...projectFiles,
          ...(threatSource === 'file' && threatFile ? [threatFile] : []),
        ];
        const totalBytes = filesToUpload.reduce((total, file) => total + file.size, 0);
        let completedBytes = 0;

        const upload = async (file: File): Promise<string> => {
          const existing = uploadedArtifactsRef.current.get(file);
          if (existing) {
            completedBytes += file.size;
            setUploadProgress(Math.round((completedBytes / totalBytes) * 100));
            return existing;
          }
          setUploadStatus(`Uploading ${file.name}`);
          const result = await uploadApplicationArtifact(appId, file, {
            onProgress: ({ bytesUploaded }) => {
              setUploadProgress(
                Math.round(((completedBytes + bytesUploaded) / totalBytes) * 100),
              );
            },
          });
          completedBytes += file.size;
          uploadedArtifactsRef.current.set(file, result.artifact.artifact_id);
          return result.artifact.artifact_id;
        };

        sourceArtifactIds = [...selectedSources];
        for (const file of projectFiles) {
          sourceArtifactIds.push(await upload(file));
        }
        threatArtifactId =
          threatSource === 'file' && threatFile
            ? await upload(threatFile)
            : null;
        setUploadProgress(100);
        setUploadStatus('Starting threat model');
      }

      const params: HostedRunConfig = {
        project_path: projectPath,
        threat_source: threatSource,
        threat_file_path:
          threatSource === 'file'
            ? isAppScoped
              ? threatFile?.name ?? null
              : threatFilePath
            : null,
        frameworks: chosenFrameworks,
        resume_run_dir: null,
        skip_nodes: [],
        app_id: isAppScoped && appId ? appId : null,
        ...(isAppScoped
          ? {
              source_artifact_ids: sourceArtifactIds,
              threat_artifact_id: threatArtifactId,
            }
          : {}),
      };
      const result = await createRun(params);
      router.push(`/runs/${result.run_id}/progress`);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : 'Failed to create run.');
    } finally {
      setSubmitting(false);
    }
  };

  const frameworkKeys = TTP_FRAMEWORK_IDS;

  const breadcrumbs: BreadcrumbGroupProps.Item[] =
    isAppScoped && appId
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
      <AppShell activePage="/applications" breadcrumbs={breadcrumbs}>
        <Box textAlign="center" padding="l" data-testid="loading-spinner">
          <Spinner size="large" />
        </Box>
      </AppShell>
    );
  }

  return (
    <AppShell activePage="/applications" breadcrumbs={breadcrumbs}>
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
              onClick={() => router.push(isAppScoped && appId ? `/applications/${appId}` : '/')}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button variant="primary" onClick={handleSubmit} loading={submitting} data-testid="start-run">
              Start threat model
            </Button>
          </SpaceBetween>
        }
      >
        <SpaceBetween size="l">
          {isAppScoped && appError && <Alert type="error">{appError}</Alert>}

          <Container header={<Header variant="h2">Project</Header>}>
            <SpaceBetween size="m">
              {isAppScoped && (
                <Alert
                  type="info"
                  header="Optional: Add more project context"
                  data-testid="additional-project-context-banner"
                >
                  Select the evidence for this run below. Deselect outdated revisions
                  when adding replacements. Each run keeps its own source selection.
                </Alert>
              )}
              {isAppScoped && sourcesLoading && <Spinner />}
              {isAppScoped && sourcesError && <Alert type="error">{sourcesError}</Alert>}
              {isAppScoped && existingSources.length > 0 && (
                <FormField label="Existing project sources" description="Only checked sources will be included alongside new uploads.">
                  <SpaceBetween size="xs">
                    {existingSources.map(source => (
                      <Checkbox key={source.artifact_id}
                        checked={selectedSources.includes(source.artifact_id)}
                        onChange={({ detail }) => setSelectedSources(previous => detail.checked
                          ? [...previous, source.artifact_id]
                          : previous.filter(id => id !== source.artifact_id))}>
                        {source.filename}{source.created_at ? ` · ${new Date(source.created_at).toLocaleString()}` : ''}
                      </Checkbox>
                    ))}
                  </SpaceBetween>
                </FormField>
              )}
              <FormField
                label={
                  isAppScoped
                    ? 'Additional files and directories (optional)'
                    : 'Project directory path'
                }
                errorText={projectPathError}
                description={
                  isAppScoped
                    ? 'New selections are added to the application workspace and included in this threat model.'
                    : 'Enter the path or browse to the project directory to analyze.'
                }
              >
                {isAppScoped ? (
                  <SpaceBetween size="s">
                    <FileUpload
                      value={sourceFiles}
                      onChange={({ detail }) => {
                        setSourceFiles(detail.value);
                        if (detail.value.length > 0) setProjectPathError('');
                      }}
                      multiple
                      showFileSize
                      tokenLimit={8}
                      constraintText="New files are uploaded securely and added to the application workspace."
                      i18nStrings={{
                        uploadButtonText: () => 'Choose files',
                        dropzoneText: () => 'Drop additional project files to upload',
                        removeFileAriaLabel: (_index, name) => `Remove ${name}`,
                        limitShowFewer: 'Show fewer files',
                        limitShowMore: 'Show more files',
                        errorIconAriaLabel: 'Error',
                        warningIconAriaLabel: 'Warning',
                      }}
                      data-testid="project-file-upload"
                    />
                    <div>
                      <input
                        ref={(element) => {
                          directoryInputRef.current = element;
                          element?.setAttribute('webkitdirectory', '');
                        }}
                        type="file"
                        multiple
                        hidden
                        data-testid="project-directory-input"
                        onChange={(event) => {
                          handleDirectorySelection(event.currentTarget.files);
                          event.currentTarget.value = '';
                        }}
                      />
                      <SpaceBetween direction="horizontal" size="xs" alignItems="center">
                        <Button
                          iconName="folder-open"
                          onClick={() => directoryInputRef.current?.click()}
                          disabled={submitting}
                        >
                          Choose directory
                        </Button>
                        {directoryFiles.length > 0 && (
                          <>
                            <Box color="text-body-secondary">
                              {directoryFiles.length} directory file
                              {directoryFiles.length === 1 ? '' : 's'} selected
                            </Box>
                            <Button
                              variant="icon"
                              iconName="close"
                              ariaLabel="Clear selected directory"
                              onClick={() => setDirectoryFiles([])}
                              disabled={submitting}
                            />
                          </>
                        )}
                      </SpaceBetween>
                    </div>
                  </SpaceBetween>
                ) : (
                  <DirectoryPicker
                    value={projectPath}
                    onChange={(val) => {
                      setProjectPath(val);
                      if (val.trim()) setProjectPathError('');
                    }}
                    placeholder="/path/to/project"
                  />
                )}
              </FormField>
            </SpaceBetween>
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
                  setThreatSource(detail.value as 'auto' | 'file');
                  if (detail.value === 'auto') setThreatFilePathError('');
                }}
                items={[
                  { value: 'auto', label: 'Auto-generate using AI' },
                  { value: 'file', label: 'Provide existing threat statements file' },
                ]}
              />
              {threatSource === 'file' && (
                <FormField
                  label={isAppScoped ? 'Threat statements file' : 'Threat file path'}
                  errorText={threatFilePathError}
                  description={
                    isAppScoped
                      ? 'Select the existing threat statements to use as authoritative input.'
                      : 'Enter the path to the threat statements file.'
                  }
                >
                  {isAppScoped ? (
                    <FileUpload
                      value={threatFile ? [threatFile] : []}
                      onChange={({ detail }) => {
                        setThreatFile(detail.value[0] ?? null);
                        if (detail.value.length > 0) setThreatFilePathError('');
                      }}
                      showFileSize
                      i18nStrings={{
                        uploadButtonText: () => 'Choose threat file',
                        dropzoneText: () => 'Drop a threat statements file to upload',
                        removeFileAriaLabel: (_index, name) => `Remove ${name}`,
                        limitShowFewer: 'Show fewer files',
                        limitShowMore: 'Show more files',
                        errorIconAriaLabel: 'Error',
                        warningIconAriaLabel: 'Warning',
                      }}
                      data-testid="threat-file-upload"
                    />
                  ) : (
                    <Input
                      value={threatFilePath}
                      onChange={({ detail }) => {
                        setThreatFilePath(detail.value);
                        if (detail.value.trim()) setThreatFilePathError('');
                      }}
                      placeholder="/path/to/threats.json"
                    />
                  )}
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
                    <Box variant="strong">{availableFrameworks[key]!.name}</Box>{' '}
                    <Box variant="small" color="text-body-secondary" display="inline">
                      — {availableFrameworks[key]!.description}
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

          {submitting && uploadStatus && (
            <ProgressBar
              value={uploadProgress}
              label={uploadStatus}
              description="Files are checked for integrity before the run starts."
              additionalInfo={`${uploadProgress}%`}
              data-testid="upload-progress"
            />
          )}
        </SpaceBetween>
      </Form>
    </AppShell>
  );
}
