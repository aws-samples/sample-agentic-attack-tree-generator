'use client';

/**
 * Route "/applications/new" — TS/Next port of console-ui's
 * pages/CreateApplicationPage.jsx.
 *
 * A 4-step wizard (identity → source → business context → review) that creates
 * the hosted application, uploads its initial evidence, and then navigates to
 * the application overview.
 */

import { useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import Wizard, { type WizardProps } from '@cloudscape-design/components/wizard';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import FileUpload from '@cloudscape-design/components/file-upload';
import Button from '@cloudscape-design/components/button';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import type { BusinessContext } from '@threatforest/types';
import AppShell from '@/components/AppShell';
import BusinessContextForm, {
  DATA_SENSITIVITY_OPTIONS,
  emptyBusinessContext,
  normaliseCiaPriority,
  validateBusinessContext,
  type BusinessContextDraft,
} from '@/components/BusinessContextForm';
import {
  createApplication,
  uploadApplicationArtifact,
} from '@/api/client';
import {
  archiveDirectoryFiles,
  directoryFileKey,
  type DirectoryFile,
} from '@/utils/directory-archive';

export default function CreateApplicationPage() {
  const router = useRouter();

  const [activeStepIndex, setActiveStepIndex] = useState(0);

  // Step 1 — identity
  const [name, setName] = useState('');
  const [nameError, setNameError] = useState('');

  // Step 2 — project source
  const [sourceFiles, setSourceFiles] = useState<File[]>([]);
  const [directoryFiles, setDirectoryFiles] = useState<DirectoryFile[]>([]);
  const [sourceError, setSourceError] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStatus, setUploadStatus] = useState('');
  const directoryInputRef = useRef<HTMLInputElement | null>(null);
  const uploadedArtifactsRef = useRef(new WeakMap<File, string>());
  const directoryArchiveRef = useRef<{
    inputs: readonly DirectoryFile[];
    archive: File;
  } | null>(null);
  const createdApplicationIdRef = useRef<string | null>(null);

  // Step 3 — business context
  const [businessContext, setBusinessContext] = useState<BusinessContextDraft>(
    emptyBusinessContext(),
  );
  const [contextErrors, setContextErrors] = useState<
    Partial<Record<keyof BusinessContextDraft, string>>
  >({});

  // Submission
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  const labelFor = (
    value: string,
    options: ReadonlyArray<{ value: string; label: string }>,
  ) => options.find((o) => o.value === value)?.label || value || '—';

  const validateStep = (stepIndex: number): boolean => {
    if (stepIndex === 0) {
      let ok = true;
      if (!name.trim()) {
        setNameError('Application name is required.');
        ok = false;
      } else {
        setNameError('');
      }
      return ok;
    }
    if (stepIndex === 1) {
      let ok = true;
      if (sourceFiles.length === 0 && directoryFiles.length === 0) {
        setSourceError('Select at least one project file or directory.');
        ok = false;
      } else if (sourceFiles.some((file) => file.size === 0)) {
        setSourceError(
          'Empty individual files cannot be uploaded. Select their directory instead.',
        );
        ok = false;
      } else {
        setSourceError('');
      }
      return ok;
    }
    if (stepIndex === 2) {
      const errors = validateBusinessContext(businessContext);
      setContextErrors(errors);
      return Object.keys(errors).length === 0;
    }
    return true;
  };

  const handleNavigate: WizardProps['onNavigate'] = (event) => {
    const { requestedStepIndex, reason } = event.detail;
    if (reason === 'next' && !validateStep(activeStepIndex)) return;
    setActiveStepIndex(requestedStepIndex);
  };

  const handleDirectorySelection = (files: FileList | null) => {
    if (!files) return;
    setDirectoryFiles((current) => {
      const byKey = new Map(current.map((file) => [directoryFileKey(file), file]));
      for (const file of Array.from(files) as DirectoryFile[]) {
        byKey.set(directoryFileKey(file), file);
      }
      return [...byKey.values()];
    });
    setSourceError('');
  };

  const handleSubmit = async () => {
    // Final defence — the wizard already validated each step, but the user
    // could still have backtracked and left something invalid.
    for (const idx of [0, 1, 2]) {
      if (!validateStep(idx)) {
        setActiveStepIndex(idx);
        return;
      }
    }

    setSubmitting(true);
    setSubmitError('');
    setUploadProgress(0);
    setUploadStatus('Creating application workspace');
    try {
      // validateStep(2) above guarantees the draft is a valid BusinessContext.
      let appId = createdApplicationIdRef.current;
      if (appId === null) {
        const app = await createApplication({
          name: name.trim(),
          projectPath: '',
          businessContext: businessContext as BusinessContext,
        });
        appId = app.id;
        createdApplicationIdRef.current = appId;
      }

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

      const totalBytes = projectFiles.reduce((total, file) => total + file.size, 0);
      let completedBytes = 0;
      for (const file of projectFiles) {
        const existing = uploadedArtifactsRef.current.get(file);
        if (existing) {
          completedBytes += file.size;
          setUploadProgress(Math.round((completedBytes / totalBytes) * 100));
          continue;
        }
        setUploadStatus(`Uploading ${file.name}`);
        const result = await uploadApplicationArtifact(appId, file, {
          onProgress: ({ bytesUploaded }) => {
            setUploadProgress(
              Math.round(((completedBytes + bytesUploaded) / totalBytes) * 100),
            );
          },
        });
        uploadedArtifactsRef.current.set(file, result.artifact.artifact_id);
        completedBytes += file.size;
      }

      setUploadProgress(100);
      setUploadStatus('Project source is ready');
      router.push(`/applications/${appId}`);
    } catch (err) {
      const message = (err as Error).message || '';
      setSubmitError(
        createdApplicationIdRef.current === null
          ? message || 'Failed to create application.'
          : `The application was created, but its source upload did not finish. ${
              message || 'Retry to continue the upload.'
            }`,
      );
      if (createdApplicationIdRef.current === null && /name/i.test(message)) {
        setActiveStepIndex(0);
        setNameError(message);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const steps: WizardProps.Step[] = [
    {
      title: 'Identity',
      description:
        'Name the application that ThreatForest should analyse.',
      content: (
        <Container header={<Header variant="h2">Identity</Header>}>
          <FormField
            label="Application name"
            description="Displayed throughout the console. Case-insensitively unique across your applications."
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
        </Container>
      ),
    },
    {
      title: 'Project source',
      description:
        'Upload files or a directory. ThreatForest stores them in the managed encrypted application workspace.',
      content: (
        <Container
          header={
            <Header
              variant="h2"
              description="Uploads are stored under an isolated per-user and per-application S3 prefix."
            >
              Project source
            </Header>
          }
        >
          <FormField
            label="Project files and directories"
            description="Select source code, documents, diagrams, images, archives, or other evidence to analyse."
            errorText={sourceError}
          >
            <SpaceBetween size="s">
              <FileUpload
                value={sourceFiles}
                onChange={({ detail }) => {
                  setSourceFiles(detail.value);
                  if (detail.value.length > 0) setSourceError('');
                }}
                multiple
                showFileSize
                tokenLimit={8}
                constraintText="Files are integrity checked, encrypted, and normalized when the application is created."
                i18nStrings={{
                  uploadButtonText: () => 'Choose files',
                  dropzoneText: () => 'Drop project files to upload',
                  removeFileAriaLabel: (_index, fileName) => `Remove ${fileName}`,
                  limitShowFewer: 'Show fewer files',
                  limitShowMore: 'Show more files',
                  errorIconAriaLabel: 'Error',
                  warningIconAriaLabel: 'Warning',
                }}
                data-testid="application-file-upload"
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
                  data-testid="application-directory-input"
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
          </FormField>
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
                for (const key of Object.keys(cleared) as Array<keyof BusinessContextDraft>) {
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
      description:
        'Confirm the details below — you can edit everything later from the app overview.',
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
                <Box variant="awsui-key-label">Project source</Box>
                <div>
                  {sourceFiles.length + directoryFiles.length} selected file
                  {sourceFiles.length + directoryFiles.length === 1 ? '' : 's'}
                </div>
              </div>
              <div>
                <Box variant="awsui-key-label">Data sensitivity</Box>
                <div>{labelFor(businessContext.data_sensitivity, DATA_SENSITIVITY_OPTIONS)}</div>
              </div>
              <div>
                <Box variant="awsui-key-label">CIA priority</Box>
                <ol
                  style={{
                    margin: 0,
                    paddingLeft: 20,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 2,
                  }}
                >
                  {normaliseCiaPriority(businessContext.cia_priority).map((v) => (
                    <li key={v} style={{ textTransform: 'capitalize' }}>
                      {v}
                    </li>
                  ))}
                </ol>
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
            {submitting && uploadStatus && (
              <ProgressBar
                value={uploadProgress}
                label={uploadStatus}
                description="ThreatForest is preparing the encrypted project workspace."
                additionalInfo={`${uploadProgress}%`}
                data-testid="application-upload-progress"
              />
            )}
          </SpaceBetween>
        </Container>
      ),
    },
  ];

  return (
    <AppShell
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
        onCancel={() => router.push('/applications')}
        isLoadingNextStep={submitting}
      />
    </AppShell>
  );
}
