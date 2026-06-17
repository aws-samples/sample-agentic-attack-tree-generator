/**
 * React Flow adapter utilities.
 * Transforms mermaid-parser output into React Flow node/edge arrays
 * and computes hierarchical layout via dagre.
 */
import dagre from '@dagrejs/dagre';
import type { Edge, Node } from '@xyflow/react';
import type { UiTTPMapping } from '@threatforest/types';
import type { ParsedGraph } from './mermaid-parser';
import type {
  RawMitigation,
  RawTtcMapping,
  ReportAttackTree,
} from './mitigation-aggregator';

/** Map of nodeId → category string (e.g. `{ A: 'attack', B: 'goal' }`). */
export type ClassDefMap = Record<string, string>;

/**
 * Extract classDef and class lines from mermaid code to build a node ID → category map.
 *
 * @param mermaidCode - The mermaid graph definition
 * @returns Map of nodeId → category string (e.g., { A: 'attack', B: 'goal' })
 */
export function parseClassDefs(mermaidCode: string | null | undefined): ClassDefMap {
  const result: ClassDefMap = {};
  if (!mermaidCode || typeof mermaidCode !== 'string') {
    return result;
  }

  const lines = mermaidCode.split('\n');
  // Track defined class names (from classDef lines)
  const definedClasses = new Set<string>();

  for (const line of lines) {
    const trimmed = line.trim();

    // Match classDef lines: classDef attack fill:#ffcccc
    const classDefMatch = trimmed.match(/^classDef\s+(\w+)\s/i);
    if (classDefMatch) {
      definedClasses.add(classDefMatch[1]!);
      continue;
    }

    // Match class assignment lines: class B,D,E,F attack
    const classMatch = trimmed.match(/^class\s+(.+?)\s+(\w+)\s*$/i);
    if (classMatch) {
      const nodeIds = classMatch[1]!.split(',').map((id) => id.trim()).filter(Boolean);
      const category = classMatch[2]!;
      for (const nodeId of nodeIds) {
        result[nodeId] = category;
      }
    }
  }

  return result;
}

/** Layout options for {@link computeDagreLayout}. */
export interface DagreLayoutOptions {
  /** Graph direction (default 'TB'). */
  direction?: string;
  /** Node width for layout (default 260). */
  nodeWidth?: number;
  /** Node height for layout (default 60). */
  nodeHeight?: number;
  /** Horizontal separation between nodes (default 50). */
  nodeSep?: number;
  /** Vertical separation between ranks (default 80). */
  rankSep?: number;
}

/**
 * Use dagre to compute hierarchical positions for React Flow nodes.
 *
 * @param nodes - React Flow nodes (positions will be overwritten)
 * @param edges - React Flow edges
 * @param options - Layout options
 * @returns Nodes with computed positions
 */
export function computeDagreLayout<N extends Node>(
  nodes: N[],
  edges: Array<Pick<Edge, 'source' | 'target'>>,
  options: DagreLayoutOptions = {},
): N[] {
  const {
    direction = 'TB',
    nodeWidth = 260,
    nodeHeight = 60,
    nodeSep = 50,
    rankSep = 80,
  } = options;

  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: direction, nodesep: nodeSep, ranksep: rankSep });

  nodes.forEach((node) => g.setNode(node.id, { width: nodeWidth, height: nodeHeight }));
  edges.forEach((edge) => g.setEdge(edge.source, edge.target));

  dagre.layout(g);

  return nodes.map((node) => {
    const pos = g.node(node.id);
    return {
      ...node,
      position: { x: pos.x - nodeWidth / 2, y: pos.y - nodeHeight / 2 },
    };
  });
}

/** The enriched `data` payload attached to each React Flow attack-tree node. */
export interface AttackTreeNodeData {
  label: string;
  nodeId: string;
  category: string;
  description: string;
  /** Matched ttc_mappings with the noisy `reasoning` field stripped. */
  ttcMappings: Array<Omit<RawTtcMapping, 'reasoning'>>;
  mitigations: RawMitigation[];
  probability: number | null;
  reachProbability: number | null;
  probabilityRationale: string;
  [key: string]: unknown;
}

/** A React Flow node produced by {@link adaptToReactFlow}. */
export type AttackTreeFlowNode = Node<AttackTreeNodeData, 'attackTreeNode'>;

/** The {nodes, edges} React Flow payload produced by {@link adaptToReactFlow}. */
export interface ReactFlowGraph {
  nodes: AttackTreeFlowNode[];
  edges: Edge[];
}

/** Per-node probability metadata gathered from the attack steps. */
interface StepProbability {
  probability: number | null;
  reachProbability: number | null;
  rationale: string;
}

/**
 * Map parseMermaidToGraph() output to React Flow format with enriched data.
 *
 * @param parserOutput - Output of {@link parseMermaidToGraph}
 * @param attackTree - Full attack tree data with attack_steps, ttc_mappings, mitigations
 * @param classDefs - Map of node ID → category string from {@link parseClassDefs}
 */
export function adaptToReactFlow(
  parserOutput: ParsedGraph | null | undefined,
  attackTree: ReportAttackTree | null | undefined,
  classDefs: ClassDefMap = {},
): ReactFlowGraph {
  const { nodes: parserNodes = [], edges: parserEdges = [] } = parserOutput || {};
  const attackSteps = (attackTree && Array.isArray(attackTree.attack_steps)) ? attackTree.attack_steps : [];
  const ttcMappings = (attackTree && Array.isArray(attackTree.ttc_mappings)) ? attackTree.ttc_mappings : [];
  const mitigations = (attackTree && Array.isArray(attackTree.mitigations)) ? attackTree.mitigations : [];

  // Build lookup maps for enrichment
  const stepMap: Record<string, string> = {};
  const stepCategoryMap: Record<string, string> = {};
  const stepProbabilityMap: Record<string, StepProbability> = {};
  for (const step of attackSteps) {
    const id = step.node_id || '';
    if (!id) continue;
    stepMap[id] = step.description || '';
    if (step.category) {
      stepCategoryMap[id] = step.category;
    }
    stepProbabilityMap[id] = {
      probability: typeof step.probability === 'number' ? step.probability : null,
      reachProbability: typeof step.reach_probability === 'number' ? step.reach_probability : null,
      rationale: step.probability_rationale || '',
    };
  }

  // Map parser nodes → React Flow nodes
  // ttc_mappings.attack_step matches by description text (label), not node ID
  // mitigations can be at tree level OR nested inside each ttc_mapping
  const rfNodes: AttackTreeFlowNode[] = parserNodes.map((node) => {
    const desc = stepMap[node.id] || '';
    const label = (node.label || '').replace(/\\n/g, ' ').replace(/\n/g, ' ');
    // Match ttc_mappings by node ID, label, or description
    const nodeMappings = ttcMappings.filter((m) =>
      m.attack_step === node.id || m.attack_step === label || m.attack_step === desc,
    ).map((m) => {
      // Strip reasoning field and duplicate data to keep popover clean
      const { reasoning, ...clean } = m;
      return clean;
    });
    // Collect mitigations from tree-level AND from inside each matched ttc_mapping
    const nodeMitigations: RawMitigation[] = mitigations.filter((m) =>
      m.attack_step === node.id || m.attack_step === label || m.attack_step === desc,
    );
    // Also pull mitigations nested inside ttc_mappings
    for (const mapping of nodeMappings) {
      if (Array.isArray(mapping.mitigations)) {
        for (const mit of mapping.mitigations) {
          // Avoid duplicates by name
          if (!nodeMitigations.some((existing) => existing.name === mit.name)) {
            nodeMitigations.push(mit);
          }
        }
      }
    }
    const prob = stepProbabilityMap[node.id] || { probability: null, reachProbability: null, rationale: '' };
    return {
      id: node.id,
      type: 'attackTreeNode',
      position: { x: 0, y: 0 },
      data: {
        label: label,
        nodeId: node.id,
        category: stepCategoryMap[node.id] || classDefs[node.id] || 'default',
        description: desc,
        ttcMappings: nodeMappings,
        mitigations: nodeMitigations,
        probability: prob.probability,
        reachProbability: prob.reachProbability,
        probabilityRationale: prob.rationale,
      },
    };
  });

  // Map parser edges → React Flow edges
  const rfEdges: Edge[] = parserEdges.map((edge) => ({
    id: `${edge.from}->${edge.to}`,
    source: edge.from,
    target: edge.to,
    markerEnd: { type: 'arrowclosed' },
    style: { stroke: '#6b7280' },
  }));

  // Compute dagre layout positions
  const layoutNodes = computeDagreLayout(rfNodes, rfEdges);

  return { nodes: layoutNodes, edges: rfEdges };
}

// `UiTTPMapping` is re-exported via the RawTtcMapping intersection in
// mitigation-aggregator; referenced here to document the matched-mapping shape.
export type { UiTTPMapping };
