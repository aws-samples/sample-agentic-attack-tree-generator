/**
 * MITRE graph build + store + vector search — TS port of
 * modules/graph/{graph_builder,graph_store,vector_search,types}.py.
 *
 * Builds a per-framework graph of techniques (each with an ATTACK-BERT embedding
 * produced by the in-process TS embedder), caches it to JSON, and does cosine
 * top-k search. The cache is keyed by embedding model + STIX mtime, so a graph
 * built by the Python service (different vectors) is treated as stale and
 * rebuilt with the JS embedder — the query and corpus must share one embedder.
 */
import { readFileSync, writeFileSync, existsSync, statSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { getBatchEmbeddings, DEFAULT_MODEL_NAME, EMBEDDING_DIM } from './embedder.js';

export interface TechniqueNode {
  id: string;
  stix_id: string;
  name: string;
  description: string;
  technique_ids: string[];
  tactics: string[];
  embedding: number[];
}

export interface MitreGraph {
  techniques: TechniqueNode[];
  embedding_model: string;
  embedding_dim: number;
  created_at: string;
  stix_version: string;
}

export interface SearchMatch {
  technique: TechniqueNode;
  similarity: number;
  confidence: 'high' | 'medium' | 'low';
}

function confidenceOf(similarity: number): 'high' | 'medium' | 'low' {
  if (similarity > 0.7) return 'high';
  if (similarity > 0.5) return 'medium';
  return 'low';
}

/** Extract attack-pattern techniques from a STIX bundle. Port of _extract_techniques. */
function extractTechniques(
  bundle: { objects?: Array<Record<string, unknown>> },
  sourceName: string,
  killChainName: string,
): Array<{ stix_id: string; name: string; description: string; external_ids: string[]; tactics: string[] }> {
  const out: Array<{
    stix_id: string;
    name: string;
    description: string;
    external_ids: string[];
    tactics: string[];
  }> = [];
  for (const obj of bundle.objects ?? []) {
    if (obj['type'] !== 'attack-pattern') continue;
    const externalIds: string[] = [];
    for (const ref of (obj['external_references'] as Array<Record<string, unknown>>) ?? []) {
      if (ref['source_name'] === sourceName && ref['external_id']) {
        externalIds.push(ref['external_id'] as string);
      }
    }
    const tactics: string[] = [];
    for (const phase of (obj['kill_chain_phases'] as Array<Record<string, unknown>>) ?? []) {
      if (phase['kill_chain_name'] === killChainName) {
        tactics.push((phase['phase_name'] as string) ?? '');
      }
    }
    out.push({
      stix_id: obj['id'] as string,
      name: (obj['name'] as string) ?? '',
      description: (obj['description'] as string) ?? '',
      external_ids: externalIds,
      tactics,
    });
  }
  return out;
}

function stixVersion(bundle: { spec_version?: string; objects?: Array<Record<string, unknown>> }): string {
  for (const obj of bundle.objects ?? []) {
    if (obj['type'] === 'x-mitre-collection') {
      const desc = (obj['description'] as string) ?? '';
      const m = desc.match(/v(\d+\.\d+)/);
      if (m) return `ATT&CK-${m[1]}`;
    }
  }
  return bundle.spec_version ?? 'unknown';
}

/** primary technique id (first external id), mirrors TechniqueNode.primary_technique_id. */
export function primaryTechniqueId(t: TechniqueNode): string {
  return t.technique_ids[0] ?? '';
}

/** Build a graph from a STIX bundle, embedding each technique with the TS embedder. */
export async function buildFromStix(
  stixBundlePath: string,
  sourceName: string,
  killChainName: string,
): Promise<MitreGraph> {
  const bundle = JSON.parse(readFileSync(stixBundlePath, 'utf8'));
  const techniques = extractTechniques(bundle, sourceName, killChainName);
  // Same text composition as Python _add_embeddings: "name: description".
  const texts = techniques.map((t) => `${t.name}: ${t.description}`);
  const embeddings = await getBatchEmbeddings(texts);

  const nodes: TechniqueNode[] = techniques.map((t, i) => {
    const primary = t.external_ids[0] ?? `tech-${i}`;
    return {
      id: `technique-${primary}`,
      stix_id: t.stix_id,
      name: t.name,
      description: t.description,
      technique_ids: t.external_ids,
      tactics: t.tactics,
      embedding: embeddings[i] ?? [],
    };
  });

  return {
    techniques: nodes,
    embedding_model: DEFAULT_MODEL_NAME,
    embedding_dim: EMBEDDING_DIM,
    created_at: new Date(0).toISOString(), // stamped by caller if needed; deterministic default
    stix_version: stixVersion(bundle),
  };
}

/** Load/save the JSON graph cache. Port of GraphStore. */
export function loadGraph(graphPath: string): MitreGraph {
  return JSON.parse(readFileSync(graphPath, 'utf8')) as MitreGraph;
}

export function saveGraph(graphPath: string, graph: MitreGraph): void {
  mkdirSync(dirname(graphPath), { recursive: true });
  writeFileSync(graphPath, JSON.stringify(graph, null, 2));
}

/** Stale if missing, wrong embedding model, or older than the STIX bundle. */
export function isStale(graphPath: string, stixBundlePath: string, expectedModel: string): boolean {
  if (!existsSync(graphPath)) return true;
  try {
    const g = loadGraph(graphPath);
    if (g.embedding_model !== expectedModel) return true;
  } catch {
    return true;
  }
  if (!existsSync(stixBundlePath)) return false;
  return statSync(stixBundlePath).mtimeMs > statSync(graphPath).mtimeMs;
}

/** Get a cached graph or build + cache it. Port of GraphBuilder.get_or_build. */
export async function getOrBuildGraph(opts: {
  graphPath: string;
  stixBundlePath: string;
  sourceName: string;
  killChainName: string;
  forceRebuild?: boolean;
}): Promise<MitreGraph> {
  const { graphPath, stixBundlePath, sourceName, killChainName, forceRebuild } = opts;
  if (!forceRebuild && !isStale(graphPath, stixBundlePath, DEFAULT_MODEL_NAME)) {
    return loadGraph(graphPath);
  }
  const graph = await buildFromStix(stixBundlePath, sourceName, killChainName);
  saveGraph(graphPath, graph);
  return graph;
}

/**
 * In-memory cosine top-k search over a graph's techniques. Port of VectorSearch.
 * Embeddings are L2-normalized at creation, so dot product == cosine.
 */
export class VectorSearch {
  private readonly matrix: number[][];
  constructor(private readonly graph: MitreGraph) {
    this.matrix = graph.techniques.map((t) => t.embedding);
  }

  search(query: number[], topK = 3, minSimilarity = 0.3): SearchMatch[] {
    if (query.length === 0) return [];
    const sims = this.matrix.map((vec) => {
      let d = 0;
      const n = Math.min(vec.length, query.length);
      for (let i = 0; i < n; i++) d += vec[i]! * query[i]!;
      return d;
    });
    // top-k indices, descending
    const idx = sims
      .map((s, i) => [s, i] as [number, number])
      .sort((a, b) => b[0] - a[0])
      .slice(0, topK);
    const out: SearchMatch[] = [];
    for (const [sim, i] of idx) {
      if (sim < minSimilarity) continue;
      out.push({ technique: this.graph.techniques[i]!, similarity: sim, confidence: confidenceOf(sim) });
    }
    return out;
  }
}
