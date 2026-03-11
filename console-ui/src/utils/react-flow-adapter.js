/**
 * React Flow adapter utilities.
 * Transforms mermaid-parser output into React Flow node/edge arrays
 * and computes hierarchical layout via dagre.
 */
import dagre from '@dagrejs/dagre';

/**
 * Extract classDef and class lines from mermaid code to build a node ID → category map.
 * @param {string} mermaidCode - The mermaid graph definition
 * @returns {Object} Map of nodeId → category string (e.g., { A: 'attack', B: 'goal' })
 */
export function parseClassDefs(mermaidCode) {
  const result = {};
  if (!mermaidCode || typeof mermaidCode !== 'string') {
    return result;
  }

  const lines = mermaidCode.split('\n');
  // Track defined class names (from classDef lines)
  const definedClasses = new Set();

  for (const line of lines) {
    const trimmed = line.trim();

    // Match classDef lines: classDef attack fill:#ffcccc
    const classDefMatch = trimmed.match(/^classDef\s+(\w+)\s/i);
    if (classDefMatch) {
      definedClasses.add(classDefMatch[1]);
      continue;
    }

    // Match class assignment lines: class B,D,E,F attack
    const classMatch = trimmed.match(/^class\s+(.+?)\s+(\w+)\s*$/i);
    if (classMatch) {
      const nodeIds = classMatch[1].split(',').map(id => id.trim()).filter(Boolean);
      const category = classMatch[2];
      for (const nodeId of nodeIds) {
        result[nodeId] = category;
      }
    }
  }

  return result;
}


/**
 * Use dagre to compute hierarchical positions for React Flow nodes.
 * @param {Array<{id: string, position?: object, data?: object}>} nodes - React Flow nodes (positions will be overwritten)
 * @param {Array<{source: string, target: string}>} edges - React Flow edges
 * @param {Object} options - Layout options
 * @param {string} [options.direction='TB'] - Graph direction
 * @param {number} [options.nodeWidth=200] - Node width for layout
 * @param {number} [options.nodeHeight=50] - Node height for layout
 * @param {number} [options.nodeSep=50] - Horizontal separation between nodes
 * @param {number} [options.rankSep=80] - Vertical separation between ranks
 * @returns {Array} Nodes with computed positions
 */
export function computeDagreLayout(nodes, edges, options = {}) {
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

  nodes.forEach(node => g.setNode(node.id, { width: nodeWidth, height: nodeHeight }));
  edges.forEach(edge => g.setEdge(edge.source, edge.target));

  dagre.layout(g);

  return nodes.map(node => {
    const pos = g.node(node.id);
    return {
      ...node,
      position: { x: pos.x - nodeWidth / 2, y: pos.y - nodeHeight / 2 },
    };
  });
}

/**
 * Map parseMermaidToGraph() output to React Flow format with enriched data.
 * @param {{ nodes: Array<{id: string, label: string, title: string}>, edges: Array<{from: string, to: string}> }} parserOutput
 * @param {Object} attackTree - Full attack tree data with attack_steps, ttc_mappings, mitigations
 * @param {Object} classDefs - Map of node ID → category string from parseClassDefs()
 * @returns {{ nodes: Array, edges: Array }}
 */
export function adaptToReactFlow(parserOutput, attackTree, classDefs = {}) {
  const { nodes: parserNodes = [], edges: parserEdges = [] } = parserOutput || {};
  const attackSteps = (attackTree && Array.isArray(attackTree.attack_steps)) ? attackTree.attack_steps : [];
  const ttcMappings = (attackTree && Array.isArray(attackTree.ttc_mappings)) ? attackTree.ttc_mappings : [];
  const mitigations = (attackTree && Array.isArray(attackTree.mitigations)) ? attackTree.mitigations : [];

  // Build lookup maps for enrichment
  const stepMap = {};
  const stepCategoryMap = {};
  for (const step of attackSteps) {
    stepMap[step.node_id] = step.description;
    if (step.category) {
      stepCategoryMap[step.node_id] = step.category;
    }
  }

  // Map parser nodes → React Flow nodes
  // ttc_mappings.attack_step matches by description text (label), not node ID
  // mitigations can be at tree level OR nested inside each ttc_mapping
  const rfNodes = parserNodes.map(node => {
    const desc = stepMap[node.id] || '';
    const label = (node.label || '').replace(/\\n/g, ' ').replace(/\n/g, ' ');
    // Match ttc_mappings by node ID, label, or description
    const nodeMappings = ttcMappings.filter(m =>
      m.attack_step === node.id || m.attack_step === label || m.attack_step === desc
    ).map(m => {
      // Strip reasoning field and duplicate data to keep popover clean
      const { reasoning, ...clean } = m;
      return clean;
    });
    // Collect mitigations from tree-level AND from inside each matched ttc_mapping
    let nodeMitigations = mitigations.filter(m =>
      m.attack_step === node.id || m.attack_step === label || m.attack_step === desc
    );
    // Also pull mitigations nested inside ttc_mappings
    for (const mapping of nodeMappings) {
      if (Array.isArray(mapping.mitigations)) {
        for (const mit of mapping.mitigations) {
          // Avoid duplicates by name
          if (!nodeMitigations.some(existing => existing.name === mit.name)) {
            nodeMitigations.push(mit);
          }
        }
      }
    }
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
      },
    };
  });

  // Map parser edges → React Flow edges
  const rfEdges = parserEdges.map(edge => ({
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
