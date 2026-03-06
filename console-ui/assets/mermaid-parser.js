/**
 * Mermaid-to-graph parser and serializer.
 * Converts mermaid "graph TD" definitions to vis-network data structures and back.
 */

/**
 * Parse a mermaid "graph TD" string into vis-network nodes and edges.
 * @param {string} mermaidCode - The mermaid graph definition
 * @param {Array<{node_id: string, description: string}>} attackSteps - Optional attack_steps array for label enrichment
 * @returns {{ nodes: Array<{id: string, label: string, title: string}>, edges: Array<{from: string, to: string}> }}
 */
export function parseMermaidToGraph(mermaidCode, attackSteps) {
  var nodes = [];
  var edges = [];
  var nodeMap = {};
  var steps = Array.isArray(attackSteps) ? attackSteps : [];

  if (!mermaidCode || typeof mermaidCode !== 'string') {
    return { nodes: nodes, edges: edges };
  }

  var lines = mermaidCode.split('\n');

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();

    // Skip empty lines, graph header, classDef and class lines
    if (!line || /^graph\s/i.test(line) || /^classDef\s/i.test(line) || /^class\s/i.test(line)) {
      continue;
    }

    // Try to parse as an edge line: ID --> ID (with optional node defs and edge labels)
    // Handles: A --> B, A["Label"] --> B["Label"], A --> |label| B
    var edgeMatch = line.match(/^(\w+)(?:\s*(?:\["[^"]*"\]|\[[^\]]*\]|\("[^"]*"\)|\([^)]*\)))?\s*-->\s*(?:\|[^|]*\|\s*)?(\w+)/);
    if (edgeMatch) {
      var fromId = edgeMatch[1];
      var toId = edgeMatch[2];
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
  for (var e = 0; e < edges.length; e++) {
    if (!nodeMap[edges[e].from]) {
      nodeMap[edges[e].from] = { id: edges[e].from, label: edges[e].from, title: '' };
    }
    if (!nodeMap[edges[e].to]) {
      nodeMap[edges[e].to] = { id: edges[e].to, label: edges[e].to, title: '' };
    }
  }

  // Build nodes array from map
  var ids = Object.keys(nodeMap);
  for (var n = 0; n < ids.length; n++) {
    nodes.push(nodeMap[ids[n]]);
  }

  // Enrich node titles from attackSteps
  var stepMap = {};
  for (var s = 0; s < steps.length; s++) {
    stepMap[steps[s].node_id] = steps[s].description;
  }
  for (var j = 0; j < nodes.length; j++) {
    if (stepMap[nodes[j].id]) {
      nodes[j].title = stepMap[nodes[j].id];
    }
  }

  return { nodes: nodes, edges: edges };
}


/**
 * Extract node definitions from a line and add them to the node map.
 * Handles patterns: ID["Label"], ID[Label], ID("Label"), ID(Label)
 * @param {string} line - A single line from the mermaid definition
 * @param {Object} nodeMap - Map of node ID to node object (mutated)
 */
function extractNodesFromLine(line, nodeMap) {
  // Match node patterns: ID["Label"], ID[Label], ID("Label"), ID(Label)
  // The regex finds all occurrences in a line (important for edge lines with node defs on both sides)
  var nodePattern = /(\w+)\s*(?:\["([^"]*?)"\]|\[([^\]]*?)\]|\("([^"]*?)"\)|\(([^)]*?)\))/g;
  var match;

  while ((match = nodePattern.exec(line)) !== null) {
    var id = match[1];
    // Label is in one of the capture groups (2-5)
    var label = match[2] !== undefined ? match[2]
      : match[3] !== undefined ? match[3]
      : match[4] !== undefined ? match[4]
      : match[5] !== undefined ? match[5]
      : id;

    if (!nodeMap[id]) {
      nodeMap[id] = { id: id, label: label, title: '' };
    }
  }
}

/**
 * Convert a parsed graph structure back to a mermaid string.
 * @param {{ nodes: Array<{id: string, label: string}>, edges: Array<{from: string, to: string}> }} graph
 * @returns {string} mermaid "graph TD" definition
 */
export function graphToMermaid(graph) {
  var lines = ['graph TD'];

  if (!graph) {
    return lines[0];
  }

  var nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  var edges = Array.isArray(graph.edges) ? graph.edges : [];

  // Track which nodes appear in edges
  var nodesInEdges = {};
  for (var e = 0; e < edges.length; e++) {
    nodesInEdges[edges[e].from] = true;
    nodesInEdges[edges[e].to] = true;
  }

  // Output standalone node definitions for nodes not in any edge
  for (var n = 0; n < nodes.length; n++) {
    if (!nodesInEdges[nodes[n].id]) {
      lines.push('    ' + nodes[n].id + '["' + nodes[n].label + '"]');
    }
  }

  // Build a node label lookup for inline definitions in edges
  var labelMap = {};
  for (var m = 0; m < nodes.length; m++) {
    labelMap[nodes[m].id] = nodes[m].label;
  }

  // Output edges with inline node definitions
  for (var i = 0; i < edges.length; i++) {
    var fromLabel = labelMap[edges[i].from] || edges[i].from;
    var toLabel = labelMap[edges[i].to] || edges[i].to;
    lines.push('    ' + edges[i].from + '["' + fromLabel + '"] --> ' + edges[i].to + '["' + toLabel + '"]');
  }

  return lines.join('\n');
}
