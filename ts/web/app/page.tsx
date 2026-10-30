'use client';

/**
 * Route "/" — marketing landing page with a context-aware primary CTA and a
 * live view of any in-flight runs.
 *
 * Previously the applications list was the home page. Per product direction
 * the root route is now a landing page again, matching the hosted deployment's
 * actual onboarding flow:
 *
 *   1. "Active runs" panel so users can jump back into a running model from
 *      any tab.
 *   2. A single context-aware CTA container that switches between:
 *      - "Set up model access" when the Configure page's Test Connection
 *        has not been run (keeps an Import-report affordance alongside,
 *        since viewing a shared report does not require a model),
 *      - "Register your first application" when the connection is verified
 *        but no applications exist yet, and
 *      - "Run a threat model" (with a paused-runs link) otherwise.
 *   3. A "How ThreatForest works" pipeline explainer.
 *
 * "Configured" requires BOTH a server-side model_id AND a matching signature
 * written to localStorage by the Configure page's successful Test Connection.
 * Save Configuration on its own is not enough — the home must know the
 * connection actually works before showing the app as ready. The hosted
 * deployment owns its AWS identity, so the signature pins model_id + region
 * (both the user can change) and leaves aws_profile empty, matching what
 * `app/configure/page.tsx` writes verbatim.
 */

import { useEffect, useState } from 'react';
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
import {
  PIPELINE_STAGES,
  buildConfigVerifiedSignature,
  pickHomeCta,
} from '@/utils/home';

export default function HomePage() {
  const router = useRouter();
  const [pausedCount, setPausedCount] = useState(0);
  const [activeRuns, setActiveRuns] = useState<RunState[]>([]);
  const [isConfigured, setIsConfigured] = useState(false);
  const [hasApps, setHasApps] = useState(false);

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
        if (!cancelled) setHasApps((data.applications || []).length > 0);
      })
      .catch(() => {});

    getConfig()
      .then((data) => {
        if (cancelled) return;
        const hasModel = Boolean(data?.model_id);
        let connectionVerified = false;
        try {
          const stored = window.localStorage.getItem('threatforest.configVerified');
          if (stored) {
            connectionVerified = stored === buildConfigVerifiedSignature(data);
          }
        } catch {
          // localStorage unavailable — treat as unverified
        }
        setIsConfigured(hasModel && connectionVerified);
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
                <Box color="text-status-inactive" fontSize="body-s">
                  Security Tool
                </Box>
                <Box fontSize="display-l" fontWeight="bold" color="inherit">
                  ThreatForest
                </Box>
                <Box fontSize="heading-l" fontWeight="light" color="inherit">
                  AI-Driven Threat Modeling for Modern Applications
                </Box>
                <Box variant="p" color="text-status-inactive" fontSize="body-s">
                  Automatically analyze your repository — source code, design documentation, or
                  both — generate attack trees, map TTPs across threat frameworks, and produce
                  actionable mitigation strategies through a multi-stage AI pipeline running on
                  AgentCore.
                </Box>
              </SpaceBetween>
              <div />
            </Grid>
          </Box>
        }
      >
        <SpaceBetween size="xl">
          {activeRuns.length > 0 && (
            <Container
              data-testid="active-runs-panel"
              header={<Header variant="h2">Active runs</Header>}
            >
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

          {(() => {
            switch (pickHomeCta(isConfigured, hasApps)) {
              case 'configure':
                return (
                  <Container
                    data-testid="cta-configure"
                    header={
                      <Header
                        variant="h2"
                        description="Pick a Bedrock model, choose a region, then run Test Connection on the Configure page. Save Configuration persists what you tested — only a verified connection unlocks running analyses. The hosted service provides its own AWS credentials."
                      >
                        Set up model access
                      </Header>
                    }
                  >
                    <SpaceBetween direction="horizontal" size="xs" alignItems="center">
                      <Button variant="primary" onClick={() => router.push('/configure')}>
                        Configure model access
                      </Button>
                      <ImportReportButton onImported={() => router.push('/applications')} />
                      <Box variant="small" color="text-body-secondary">
                        Required once per account. Imported reports open without a verified model.
                      </Box>
                    </SpaceBetween>
                  </Container>
                );
              case 'create-first-app':
                return (
                  <Container
                    data-testid="cta-create-first-app"
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
              case 'run':
                return (
                  <Container
                    data-testid="cta-run"
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
                            data-testid="resume-paused-link"
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
            }
          })()}

          <Container
            header={
              <Header
                variant="h2"
                description="ThreatForest analyzes your repository through a multi-stage pipeline to produce a complete threat model."
              >
                How ThreatForest works
              </Header>
            }
          >
            <ColumnLayout columns={3} variant="text-grid">
              {PIPELINE_STAGES.map((stage, index) => (
                <SpaceBetween key={stage.title} size="xs">
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
