'use client';

/**
 * Route "/" — TS/Next port of console-ui's pages/HomePage.jsx.
 *
 * Uses Next's router instead of react-router; the data-loading, config-verified
 * gating, and context-aware primary action are a faithful port of the legacy
 * page.
 */

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Grid from '@cloudscape-design/components/grid';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Link from '@cloudscape-design/components/link';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import type { RunState } from '@threatforest/types';
import AppShell from '@/components/AppShell';
import ImportReportButton from '@/components/ImportReportButton';
import {
  getPausedRuns,
  getActiveRuns,
  getConfig,
  getApplications,
} from '@/api/client';

interface PipelineStage {
  title: string;
  description: string;
}

// Not exported: Next.js page modules may only export a default component +
// reserved fields (metadata, generateStaticParams, etc.). This stays module-local.
const PIPELINE_STAGES: ReadonlyArray<PipelineStage> = [
  { title: 'Repository Analysis', description: 'Scans your repository — code, design docs, or both — to identify components, dependencies, and potential attack surfaces' },
  { title: 'Threat Parsing', description: 'Analyzes identified components to extract and categorize potential threats' },
  { title: 'Attack Tree Generation', description: 'Builds structured attack trees modeling how threats can be exploited' },
  { title: 'TTP Enrichment', description: 'Maps attack paths to industry repositories of tactics, techniques, and procedures' },
  { title: 'Mitigation Mapping', description: 'Generates actionable mitigation strategies for each identified attack path' },
  { title: 'Dashboard Generation', description: 'Produces an interactive dashboard for exploring threats, attack trees, and mitigations' },
];

export default function HomePage() {
  const router = useRouter();
  const [pausedCount, setPausedCount] = useState(0);
  const [activeRuns, setActiveRuns] = useState<RunState[]>([]);
  const [isConfigured, setIsConfigured] = useState(false);
  const [applications, setApplications] = useState<unknown[]>([]);

  useEffect(() => {
    let cancelled = false;
    getPausedRuns()
      .then((data) => {
        if (!cancelled) setPausedCount((data.paused_runs || []).length);
      })
      .catch(() => {});
    getActiveRuns()
      .then((data) => {
        if (!cancelled) setActiveRuns(data.runs || []);
      })
      .catch(() => {});
    getApplications()
      .then((data) => {
        if (!cancelled) setApplications(data?.applications || []);
      })
      .catch(() => {});
    getConfig()
      .then((data) => {
        if (cancelled) return;
        const hasProfile = Boolean(data?.aws_profile);
        const hasModel = Boolean(data?.model_provider && data?.model_id);
        let connectionVerified = false;
        try {
          const stored = window.localStorage.getItem('threatforest.configVerified');
          if (stored) {
            const expected = JSON.stringify({
              provider: data?.model_provider || '',
              model_id: data?.model_id || '',
              aws_profile: data?.aws_profile || '',
            });
            connectionVerified = stored === expected;
          }
        } catch {
          // localStorage unavailable — treat as unverified
        }
        setIsConfigured(hasProfile && hasModel && connectionVerified);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <AppShell activePage="/" breadcrumbs={[]} headerVariant="high-contrast">
      <ContentLayout
        headerVariant="high-contrast"
        header={
          <Box padding={{ top: 'xl', bottom: 'xl' }}>
            <Grid gridDefinition={[{ colspan: 8 }, { colspan: 4 }]}>
              <SpaceBetween size="l">
                <Box color="text-status-inactive" fontSize="body-s">Security Tool</Box>
                <Box fontSize="display-l" fontWeight="bold" color="inherit">
                  ThreatForest
                </Box>
                <Box fontSize="heading-l" fontWeight="light" color="inherit">
                  AI-Driven Threat Modeling for Modern Applications
                </Box>
                <Box variant="p" color="text-status-inactive" fontSize="body-s">
                  Automatically analyze your repository — source code, design documentation, or both —
                  generate attack trees, map TTPs across threat frameworks, and produce actionable
                  mitigation strategies through a multi-stage AI pipeline.
                </Box>
              </SpaceBetween>
              <div />
            </Grid>
          </Box>
        }
      >
        <SpaceBetween size="xl">
          {/* Active Runs */}
          {activeRuns.length > 0 && (
            <Container header={<Header variant="h2">Active runs</Header>}>
              <SpaceBetween size="s">
                {activeRuns.map((run) => (
                  <Box key={run.run_id}>
                    <SpaceBetween direction="horizontal" size="s" alignItems="center">
                      <StatusIndicator type="in-progress">
                        {run.status === 'pending' ? 'Starting' : 'Running'}
                      </StatusIndicator>
                      <Box variant="span" color="text-body-secondary">
                        {run.config?.project_path?.split('/').pop() || run.run_id}
                      </Box>
                      <Link
                        onFollow={(e) => {
                          e.preventDefault();
                          router.push(`/runs/${run.run_id}/progress`);
                        }}
                      >
                        View progress
                      </Link>
                    </SpaceBetween>
                  </Box>
                ))}
              </SpaceBetween>
            </Container>
          )}

          {/* Context-aware primary action */}
          {(() => {
            const hasApps = applications.length > 0;

            if (!isConfigured) {
              return (
                <Container
                  header={
                    <Header
                      variant="h2"
                      description="Connect ThreatForest to a model provider before running your first analysis — or import a report someone shared with you to view it without running the pipeline."
                    >
                      Get started
                    </Header>
                  }
                >
                  <SpaceBetween direction="horizontal" size="xs" alignItems="center">
                    <Button variant="primary" onClick={() => router.push('/configure')}>
                      Configure model access
                    </Button>
                    <ImportReportButton onImported={() => router.push('/applications')} />
                    <Box variant="small" color="text-body-secondary">
                      Configuration is required to run analyses. Imports work without a provider.
                    </Box>
                  </SpaceBetween>
                </Container>
              );
            }

            if (!hasApps) {
              return (
                <Container
                  header={
                    <Header
                      variant="h2"
                      description="Register a repository — source code, design documentation, or both — so ThreatForest can analyze it and track threat models over time."
                    >
                      Register your first application
                    </Header>
                  }
                >
                  <SpaceBetween direction="horizontal" size="xs" alignItems="center">
                    <Button variant="primary" onClick={() => router.push('/applications/new')}>
                      Create application
                    </Button>
                    <Button variant="link" onClick={() => router.push('/configure')}>
                      Update model configuration
                    </Button>
                  </SpaceBetween>
                </Container>
              );
            }

            return (
              <Container
                header={
                  <Header
                    variant="h2"
                    description="Pick up where you left off or register a new application."
                  >
                    Run a threat model
                  </Header>
                }
              >
                <SpaceBetween size="s">
                  <SpaceBetween direction="horizontal" size="xs" alignItems="center">
                    <Button variant="primary" onClick={() => router.push('/applications')}>
                      Open an application
                    </Button>
                    <Button onClick={() => router.push('/applications/new')}>
                      Create application
                    </Button>
                    <Button variant="link" onClick={() => router.push('/configure')}>
                      Update model configuration
                    </Button>
                  </SpaceBetween>
                  {pausedCount > 0 && (
                    <Box>
                      <Link
                        onFollow={(e) => {
                          e.preventDefault();
                          router.push('/paused-runs');
                        }}
                      >
                        Resume paused runs ({pausedCount})
                      </Link>
                    </Box>
                  )}
                </SpaceBetween>
              </Container>
            );
          })()}

          {/* What ThreatForest does — pipeline explainer */}
          <Container
            header={
              <Header
                variant="h2"
                description="ThreatForest analyzes your repository through a multi stage pipeline to produce a complete threat model."
              >
                How ThreatForest works
              </Header>
            }
          >
            <ColumnLayout columns={3} variant="text-grid">
              {PIPELINE_STAGES.map((stage, index) => (
                <SpaceBetween key={index} size="xs">
                  <Box variant="awsui-key-label">{`Stage ${index + 1}`}</Box>
                  <Box variant="h3">{stage.title}</Box>
                  <Box color="text-body-secondary">{stage.description}</Box>
                </SpaceBetween>
              ))}
            </ColumnLayout>
          </Container>
        </SpaceBetween>
      </ContentLayout>
    </AppShell>
  );
}
