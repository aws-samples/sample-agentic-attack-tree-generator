import React from 'react';
import { useNavigate } from 'react-router-dom';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Grid from '@cloudscape-design/components/grid';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import CloudscapeShell from '../components/CloudscapeShell';

export const PIPELINE_STAGES = [
  { title: 'Repository Analysis', description: 'Scans your codebase to identify components, dependencies, and potential attack surfaces' },
  { title: 'Threat Parsing', description: 'Analyzes identified components to extract and categorize potential threats' },
  { title: 'Attack Tree Generation', description: 'Builds structured attack trees modeling how threats can be exploited' },
  { title: 'TTP Enrichment', description: 'Maps attack paths to threat framework techniques (ATT&CK, ATLAS, and more)' },
  { title: 'Mitigation Mapping', description: 'Generates actionable mitigation strategies for each identified attack path' },
  { title: 'Dashboard Generation', description: 'Produces an interactive dashboard for exploring threats, attack trees, and mitigations' },
];

export default function HomePage() {
  const navigate = useNavigate();

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
                Start a new ThreatForest analysis run to scan your repository, generate attack trees,
                and produce actionable security insights.
              </Box>
              <Button variant="primary" onClick={() => navigate('/new-run')}>
                Start New Run
              </Button>
            </SpaceBetween>
          </Container>
        }
      >
        <SpaceBetween size="xl">
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
                <Box variant="h3">Start run</Box>
                <Box variant="p">
                  Provide a repository URL and start the ThreatForest analysis pipeline
                </Box>
                <button
                  className="aws-orange-btn"
                  onClick={() => navigate('/new-run')}
                >
                  Start a run
                </button>
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
