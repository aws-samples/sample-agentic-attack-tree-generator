import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
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
import CloudscapeShell from '../components/CloudscapeShell';
import { getPausedRuns, getActiveRuns } from '../api-client';

export const PIPELINE_STAGES = [
  { title: 'Repository Analysis', description: 'Scans your codebase to identify components, dependencies, and potential attack surfaces' },
  { title: 'Threat Parsing', description: 'Analyzes identified components to extract and categorize potential threats' },
  { title: 'Attack Tree Generation', description: 'Builds structured attack trees modeling how threats can be exploited' },
  { title: 'TTP Enrichment', description: 'Maps attack paths to industry repositories of tactics, techniques, and procedures' },
  { title: 'Mitigation Mapping', description: 'Generates actionable mitigation strategies for each identified attack path' },
  { title: 'Dashboard Generation', description: 'Produces an interactive dashboard for exploring threats, attack trees, and mitigations' },
];

export default function HomePage() {
  const navigate = useNavigate();
  const [pausedCount, setPausedCount] = useState(0);
  const [activeRuns, setActiveRuns] = useState([]);

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
    return () => { cancelled = true; };
  }, []);

  return (
    <CloudscapeShell activePage="/" breadcrumbs={[]} headerVariant="high-contrast">
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
                  Automatically analyze your codebase, generate attack trees, map TTPs across threat frameworks,
                  and produce actionable mitigation strategies — all through a 6-stage AI pipeline.
                </Box>
              </SpaceBetween>
              <div />
            </Grid>
          </Box>
        }
        secondaryHeader={
          <Container header={<Header variant="h2">Get started with ThreatForest</Header>}>
            <SpaceBetween size="m">
              <Box variant="p">
                Register an application with its business context, then start a
                threat model to scan the repository, generate attack trees, and
                produce actionable security insights.
              </Box>
              <SpaceBetween direction="horizontal" size="s">
                <Button variant="primary" onClick={() => navigate('/applications/new')}>
                  Create application
                </Button>
                <Button onClick={() => navigate('/applications')}>
                  View applications
                </Button>
              </SpaceBetween>
            </SpaceBetween>
          </Container>
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
                          navigate(`/runs/${run.run_id}/progress`);
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

          {/* Getting Started Steps */}
          <Container header={<Header variant="h2">Getting started</Header>}>
            <ColumnLayout columns={3}>
              <SpaceBetween size="s">
                <Box fontSize="heading-l" fontWeight="bold">Step 1</Box>
                <Box variant="h3">Configure credentials and model access</Box>
                <Box variant="p">
                  Set up your AWS credentials and configure model access for the AI pipeline
                </Box>
                <button
                  className="aws-orange-btn"
                  onClick={() => navigate('/configure')}
                >
                  Configure
                </button>
              </SpaceBetween>
              <SpaceBetween size="s">
                <Box fontSize="heading-l" fontWeight="bold">Step 2</Box>
                <Box variant="h3">Create threat model</Box>
                <Box variant="p">
                  Register an application with its business context, then launch
                  the ThreatForest analysis pipeline from the app overview.
                </Box>
                <button
                  className="aws-orange-btn"
                  onClick={() => navigate('/applications/new')}
                >
                  Create application
                </button>
                {pausedCount > 0 && (
                  <Button
                    variant="link"
                    iconName="status-in-progress"
                    onClick={() => navigate('/paused-runs')}
                  >
                    Resume paused runs ({pausedCount})
                  </Button>
                )}
              </SpaceBetween>
              <SpaceBetween size="s">
                <Box fontSize="heading-l" fontWeight="bold">Step 3</Box>
                <Box variant="h3">View dashboard</Box>
                <Box variant="p">
                  Explore generated attack trees, threats, and mitigations in the interactive dashboard
                </Box>
                <button
                  className="aws-orange-btn"
                  onClick={() => navigate('/applications')}
                >
                  View dashboard
                </button>
              </SpaceBetween>
            </ColumnLayout>
          </Container>

          {/* How It Works */}
          <Container header={<Header variant="h2">How it works</Header>}>
            <ColumnLayout columns={3} variant="text-grid">
              {PIPELINE_STAGES.map((stage, index) => (
                <SpaceBetween key={index} size="s">
                  <Box variant="h3">{stage.title}</Box>
                  <Box>{stage.description}</Box>
                </SpaceBetween>
              ))}
            </ColumnLayout>
          </Container>
        </SpaceBetween>
      </ContentLayout>
    </CloudscapeShell>
  );
}
