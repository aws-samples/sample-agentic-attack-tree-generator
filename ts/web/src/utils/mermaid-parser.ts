/**
 * Mermaid-to-graph parser and serializer.
 * Converts mermaid "graph TD" definitions to vis-network data structures and back.
 *
 * The node/edge shapes here are the parser's own vis-network-flavoured tuples
 * (`{id, label, title}` / `{from, to}`), distinct from the strict
 * `AttackNode`/`AttackEdge` schemas in `@threatforest/types`. The optional
 * `attackSteps` enrichment argument matches the report-bundle attack-step shape.
 */

/** A node parsed out of a mermaid graph (vis-network flavoured). */
export interface ParsedNode {
  id: string;
  label: string;
  title: string;
}

/** A directed edge parsed out of a mermaid graph. */
export interface ParsedEdge {
  from: string;
  to: string;
}

/** The result of {@link parseMermaidToGraph}. */
export interface ParsedGraph {
  nodes: ParsedNode[];
  edges: ParsedEdge[];
}

/** Minimal attack-step shape used for label/title enrichment. */
export interface MermaidAttackStep {
  node_id: string;
  description: string;
}

/**
 * Parse a mermaid "graph TD" string into vis-network nodes and edges.
 *
 * @param mermaidCode - The mermaid graph definition
 * @param attackSteps - Optional attack_steps array for label enrichment
 */
export function parseMermaidToGraph(
  mermaidCode: string | null | undefined,
  attackSteps?: ReadonlyArray<Partial<MermaidAttackStep>> | null,
): ParsedGraph {
  const nodes: ParsedNode[] = [];
  const edges: ParsedEdge[] = [];
  const nodeMap: Record<string, ParsedNode> = {};
  const steps = Array.isArray(attackSteps) ? attackSteps : [];

  if (!mermaidCode || typeof mermaidCode !== 'string') {
    return { nodes: nodes, edges: edges };
  }

  const lines = mermaidCode.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();

    // Skip empty lines, graph header, classDef and class lines
    if (!line || /^graph\s/i.test(line) || /^classDef\s/i.test(line) || /^class\s/i.test(line)) {
      continue;
    }

    // Try to parse as an edge line: ID --> ID (with optional node defs and edge labels)
    // Handles: A --> B, A["Label"] --> B["Label"], A --> |label| B
    const edgeMatch = line.match(/^(\w+)(?:\s*(?:\["[^"]*"\]|\[[^\]]*\]|\("[^"]*"\)|\([^)]*\)))?\s*-->\s*(?:\|[^|]*\|\s*)?(\w+)/);
    if (edgeMatch) {
      const fromId = edgeMatch[1]!;
      const toId = edgeMatch[2]!;
      edges.push({ from: fromId, to: toId });

      // Extract node definitions from the edge line itself
      // e.g. A["Label"] --> B["Label"]
      extractNodesFromLine(line, nodeMap);
      continue;
    }

    // Try to parse as a standalone node definition
    extractNodesFromLine(line, nodeMap);
  }

  // Ensure all nodes referenced in edges exist
  for (let e = 0; e < edges.length; e++) {
    const edge = edges[e]!;
    if (!nodeMap[edge.from]) {
      nodeMap[edge.from] = { id: edge.from, label: edge.from, title: '' };
    }
    if (!nodeMap[edge.to]) {
      nodeMap[edge.to] = { id: edge.to, label: edge.to, title: '' };
    }
  }

  // Build nodes array from map
  const ids = Object.keys(nodeMap);
  for (let n = 0; n < ids.length; n++) {
    nodes.push(nodeMap[ids[n]!]!);
  }

  // Enrich node titles from attackSteps
  const stepMap: Record<string, string> = {};
  for (let s = 0; s < steps.length; s++) {
    const step = steps[s]!;
    if (step.node_id) stepMap[step.node_id] = step.description ?? '';
  }
  for (let j = 0; j < nodes.length; j++) {
    const node = nodes[j]!;
    if (stepMap[node.id]) {
      node.title = stepMap[node.id]!;
    }
  }

  return { nodes: nodes, edges: edges };
}


/**
 * Extract node definitions from a line and add them to the node map.
 * Handles patterns: ID["Label"], ID[Label], ID("Label"), ID(Label)
 *
 * @param line - A single line from the mermaid definition
 * @param nodeMap - Map of node ID to node object (mutated)
 */
function extractNodesFromLine(line: string, nodeMap: Record<string, ParsedNode>): void {
  // Match node patterns: ID["Label"], ID[Label], ID("Label"), ID(Label)
  // The regex finds all occurrences in a line (important for edge lines with node defs on both sides)
  const nodePattern = /(\w+)\s*(?:\["([^"]*?)"\]|\[([^\]]*?)\]|\("([^"]*?)"\)|\(([^)]*?)\))/g;
  let match: RegExpExecArray | null;

  while ((match = nodePattern.exec(line)) !== null) {
    const id = match[1]!;
    // Label is in one of the capture groups (2-5)
    const label = match[2] !== undefined ? match[2]
      : match[3] !== undefined ? match[3]
      : match[4] !== undefined ? match[4]
      : match[5] !== undefined ? match[5]
      : id;

    if (!nodeMap[id]) {
      nodeMap[id] = { id: id, label: label, title: '' };
    }
  }
}

/** Minimal graph shape {@link graphToMermaid} serializes. */
export interface SerializableGraph {
  nodes?: Array<{ id: string; label: string }>;
  edges?: ParsedEdge[];
}

/**
 * Convert a parsed graph structure back to a mermaid string.
 */
export function graphToMermaid(graph: SerializableGraph | null | undefined): string {
  const lines = ['graph TD'];

  if (!graph) {
    return lines[0]!;
  }

  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];

  // Track which nodes appear in edges
  const nodesInEdges: Record<string, boolean> = {};
  for (let e = 0; e < edges.length; e++) {
    nodesInEdges[edges[e]!.from] = true;
    nodesInEdges[edges[e]!.to] = true;
  }

  // Output standalone node definitions for nodes not in any edge
  for (let n = 0; n < nodes.length; n++) {
    const node = nodes[n]!;
    if (!nodesInEdges[node.id]) {
      lines.push('    ' + node.id + '["' + node.label + '"]');
    }
  }

  // Build a node label lookup for inline definitions in edges
  const labelMap: Record<string, string> = {};
  for (let m = 0; m < nodes.length; m++) {
    labelMap[nodes[m]!.id] = nodes[m]!.label;
  }

  // Output edges with inline node definitions
  for (let i = 0; i < edges.length; i++) {
    const edge = edges[i]!;
    const fromLabel = labelMap[edge.from] || edge.from;
    const toLabel = labelMap[edge.to] || edge.to;
    lines.push('    ' + edge.from + '["' + fromLabel + '"] --> ' + edge.to + '["' + toLabel + '"]');
  }

  return lines.join('\n');
}
