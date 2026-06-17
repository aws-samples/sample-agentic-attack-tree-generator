/**
 * In-process TTC matcher — TS port of
 * modules/workflow/ttc_mappings/matcher.py (TTCMatcher).
 *
 * Embeds attack-step descriptions with the in-process ATTACK-BERT embedder and
 * matches them to MITRE techniques across the configured frameworks, applying
 * the same AWS-term boost and cross-framework top-k merge as the Python. Returns
 * the SAME shape as MlServiceClient.matchSteps (StepMatch[]) so the TTP stage is
 * agnostic to whether matching is in-process TS or the Python service.
 *
 * Graphs are built once (per framework) with the JS embedder and cached under
 * .threatforest/graphs/<fw>_graph_basel_ATTACK-BERT.json, then held warm.
 */
import { join } from 'node:path';
import type { StepMatch, TechniqueMatch } from '@threatforest/types';
import { config } from '../config.js';
import { getEmbedding } from './embedder.js';
import { getOrBuildGraph, VectorSearch, primaryTechniqueId, type MitreGraph } from './graph.js';

const AWS_TERMS = [
  'aws', 's3', 'ec2', 'iam', 'lambda', 'dynamodb', 'rds', 'ecs', 'cloudformation',
  'cloudwatch', 'sns', 'sqs', 'kinesis', 'athena', 'glue', 'emr', 'eks', 'fargate',
  'bucket', 'instance', 'role', 'cloudtrail', 'kms', 'secrets', 'parameter', 'api', 'gateway',
];

function confidenceOf(similarity: number): 'high' | 'medium' | 'low' {
  if (similarity > 0.7) return 'high';
  if (similarity > 0.5) return 'medium';
  return 'low';
}

/** Resolve the STIX bundle + graph-cache paths for a framework (mirrors Config). */
function frameworkPaths(fwKey: string): {
  stixBundlePath: string;
  graphPath: string;
  sourceName: string;
  killChainName: string;
} | null {
  const fw = config.frameworks[fwKey];
  if (!fw) return null;
  // STIX bundles live in the Python package data dir (kept); resolve relative to cwd.
  const dataDir =
    process.env.TF_STIX_DIR ||
    join(process.cwd(), 'src', 'threatforest', 'data', 'threat-intelligence');
  const graphsDir =
    process.env.TF_GRAPHS_DIR || join(process.cwd(), '.threatforest', 'graphs');
  const modelSlug = config.embeddingsModel.replace(/[/\\]/g, '_');
  return {
    stixBundlePath: join(dataDir, fw.stix_bundle ?? 'enterprise-attack-18.0.json'),
    graphPath: join(graphsDir, `${fwKey}_graph_${modelSlug}.json`),
    sourceName: fw.source_name ?? 'mitre-attack',
    killChainName: fw.kill_chain_name ?? 'mitre-attack',
  };
}

/** Warm per-(framework) search index cache. */
const _searches = new Map<string, VectorSearch>();

async function getSearch(fwKey: string): Promise<VectorSearch | null> {
  const cached = _searches.get(fwKey);
  if (cached) return cached;
  const paths = frameworkPaths(fwKey);
  if (!paths) return null;
  const graph: MitreGraph = await getOrBuildGraph({
    graphPath: paths.graphPath,
    stixBundlePath: paths.stixBundlePath,
    sourceName: paths.sourceName,
    killChainName: paths.killChainName,
  });
  const vs = new VectorSearch(graph);
  _searches.set(fwKey, vs);
  return vs;
}

function round4(x: number): number {
  return Math.round(x * 1e4) / 1e4;
}

/**
 * Match attack steps to techniques across frameworks. Faithful port of
 * TTCMatcher.match_steps — returns one entry per matched step (steps with no
 * match above threshold are omitted), top-k merged across frameworks, with the
 * AWS-term boost applied.
 */
export async function matchStepsInProcess(
  steps: string[],
  opts: { topK?: number; minSimilarity?: number | null; frameworks?: string[] | null } = {},
): Promise<StepMatch[]> {
  const topK = opts.topK ?? 3;
  const minSimilarity = opts.minSimilarity ?? config.ttcThreshold;
  const fwKeys = opts.frameworks ?? Object.keys(config.frameworks);

  const searches: Array<{ key: string; vs: VectorSearch }> = [];
  for (const key of fwKeys) {
    const vs = await getSearch(key);
    if (vs) searches.push({ key, vs });
  }

  const results: StepMatch[] = [];
  for (const step of steps) {
    const stepEmbedding = await getEmbedding(step);
    if (stepEmbedding.length === 0) continue;

    const stepLower = step.toLowerCase();
    const awsTermsInStep = AWS_TERMS.filter((t) => stepLower.includes(t));

    const allMatches: TechniqueMatch[] = [];
    for (const { key, vs } of searches) {
      for (const result of vs.search(stepEmbedding, topK, minSimilarity)) {
        let similarity = result.similarity;
        const tech = result.technique;
        if (awsTermsInStep.length > 0) {
          const techText = `${tech.name} ${tech.description}`.toLowerCase();
          const matchingTerms = awsTermsInStep.filter((t) => techText.includes(t));
          if (matchingTerms.length > 0) {
            const boost = 1.0 + 0.1 * matchingTerms.length;
            similarity *= Math.min(boost, 1.5);
            if (similarity < minSimilarity) continue;
          }
        }
        allMatches.push({
          technique_id: primaryTechniqueId(tech),
          name: tech.name,
          description: tech.description,
          kill_chain_phases: tech.tactics,
          similarity,
          confidence: confidenceOf(similarity),
          framework: key,
        });
      }
    }

    allMatches.sort((a, b) => b.similarity - a.similarity);
    const topMatches = allMatches.slice(0, topK);
    if (topMatches.length > 0) {
      results.push({ attack_step: step, matches: topMatches });
    }
  }
  return results;
}

export { round4 as _round4ForTests };
