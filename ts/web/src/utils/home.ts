/**
 * Pure helpers for the "/" landing page.
 *
 * Isolated from the JSX-heavy page component so they can be exercised without
 * a DOM: `pickHomeCta` encodes the primary-CTA state machine,
 * `buildConfigVerifiedSignature` mirrors the exact shape the Configure page's
 * Test Connection step writes to localStorage, and `PIPELINE_STAGES` is the
 * content of the "How ThreatForest works" explainer.
 *
 * The AgentCore hosted deployment owns its AWS identity: the user picks a
 * Bedrock model and a region, but has no `aws_profile`. The signature pins the
 * fields the Configure page tested against so a region change or model change
 * invalidates the "verified" state until the next successful test.
 */

/** Which CTA container the home page renders, given the observed state. */
export type HomeCta = 'configure' | 'create-first-app' | 'run';

/**
 * Decide which single CTA the home page should surface.
 *
 * Linear escalation:
 *   - unverified connection → prompt to configure;
 *   - verified but no apps → prompt to create one;
 *   - otherwise → offer the "run a threat model" panel (with a paused-runs link).
 *
 * `isConfigured` should already reflect BOTH server-side config (a saved
 * model_id) AND a matching signature in localStorage from the Configure page's
 * successful Test Connection — saving alone is not enough.
 */
export function pickHomeCta(isConfigured: boolean, hasApps: boolean): HomeCta {
  if (!isConfigured) return 'configure';
  if (!hasApps) return 'create-first-app';
  return 'run';
}

export interface PipelineStage {
  readonly title: string;
  readonly description: string;
}

export const PIPELINE_STAGES: ReadonlyArray<PipelineStage> = [
  {
    title: 'Repository Analysis',
    description:
      'Scans your repository — code, design docs, or both — to identify components, dependencies, and potential attack surfaces',
  },
  {
    title: 'Threat Parsing',
    description:
      'Analyzes identified components to extract and categorize potential threats, with optional human-in-the-loop review',
  },
  {
    title: 'Attack Tree Generation',
    description: 'Builds structured attack trees modeling how threats can be exploited',
  },
  {
    title: 'TTP Enrichment',
    description:
      'Maps attack paths to industry repositories of tactics, techniques, and procedures',
  },
  {
    title: 'Mitigation Mapping',
    description: 'Generates actionable mitigation strategies for each identified attack path',
  },
  {
    title: 'Dashboard Generation',
    description:
      'Produces an interactive dashboard for exploring threats, attack trees, and mitigations',
  },
];

/**
 * Build the localStorage-signature string the Configure page writes on a
 * successful Test Connection. The home page reads and compares it to the
 * current server config; any drift (new model_id, new region, …) and the
 * configuration is treated as unverified until the user re-tests.
 *
 * Shape intentionally matches `app/configure/page.tsx` verbatim (hosted
 * deployment: provider is hardcoded to "AWS Bedrock" and `aws_profile` is
 * always empty — the service runs under its own task role).
 */
export function buildConfigVerifiedSignature(config: {
  model_id?: string | null;
  aws_region?: string | null;
}): string {
  return JSON.stringify({
    provider: 'AWS Bedrock',
    model_id: config.model_id || '',
    aws_region: config.aws_region || '',
    aws_profile: '',
  });
}
