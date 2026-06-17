'use client';

/**
 * Temporary scaffold body for not-yet-ported pages.
 *
 * Renders the page title inside the Cloudscape shell plus a TODO note listing
 * which legacy component(s) still need porting. This keeps the route tree
 * typechecking and navigable while the heavy components (graph viewer, tables,
 * export, forms) are migrated in a follow-up.
 */

import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import type { BreadcrumbGroupProps } from '@cloudscape-design/components/breadcrumb-group';
import AppShell from './AppShell';

export interface PagePlaceholderProps {
  /** Page title shown in the content header. */
  title: string;
  /** Short description of what the finished page will do. */
  description?: string;
  /** Names of the legacy console-ui component(s) this page must port. */
  portsFrom?: string[];
  /** Side-nav highlight + breadcrumbs forwarded to the shell. */
  activePage?: string;
  breadcrumbs?: BreadcrumbGroupProps.Item[];
}

export default function PagePlaceholder({
  title,
  description,
  portsFrom,
  activePage,
  breadcrumbs,
}: PagePlaceholderProps) {
  return (
    <AppShell activePage={activePage} breadcrumbs={breadcrumbs}>
      <ContentLayout header={<Header variant="h1" description={description}>{title}</Header>}>
        <Container header={<Header variant="h2">Placeholder</Header>}>
          <SpaceBetween size="s">
            <Box variant="p">
              TODO: port this page from the legacy Vite SPA. This is a routing
              skeleton — the API client and routes are in place; the page body is
              not yet implemented.
            </Box>
            {portsFrom && portsFrom.length > 0 ? (
              <Box variant="p" color="text-status-info">
                Ports from: {portsFrom.join(', ')}
              </Box>
            ) : null}
          </SpaceBetween>
        </Container>
      </ContentLayout>
    </AppShell>
  );
}
