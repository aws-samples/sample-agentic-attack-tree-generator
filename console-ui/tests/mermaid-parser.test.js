import { describe, it, expect } from 'vitest';
import { parseMermaidToGraph, graphToMermaid } from '../assets/mermaid-parser.js';

describe('parseMermaidToGraph', () => {
  it('parses sample mermaid code with quoted labels', () => {
    var mermaid = [
      'graph TD',
      '    A["Malicious attacker with physical access to IoT devices"] --> B["Physical device acquisition"]',
      '    B --> C["Firmware extraction"]',
      '    C --> D["Direct memory dump via JTAGSWD"]',
      '    C --> E["Flash chip removal and reading"]',
      '    C --> F["Firmware download via debug interface"]',
      '    D --> G["Analyze extracted firmware"]',
      '    E --> G',
      '    F --> G',
      '    G --> H["Locate credential storage"]',
      '    H --> I["Extract X.509 certificates"]',
      '    H --> J["Extract private keys"]',
    ].join('\n');

    var result = parseMermaidToGraph(mermaid);

    // Should have 10 unique nodes (A through J)
    expect(result.nodes.length).toBe(10);
    // Should have 11 edges
    expect(result.edges.length).toBe(11);

    // Check specific node labels
    var nodeA = result.nodes.find(function (n) { return n.id === 'A'; });
    expect(nodeA.label).toBe('Malicious attacker with physical access to IoT devices');

    var nodeD = result.nodes.find(function (n) { return n.id === 'D'; });
    expect(nodeD.label).toBe('Direct memory dump via JTAGSWD');

    // Nodes E and G that appear only in edges without definitions should still exist
    var nodeE = result.nodes.find(function (n) { return n.id === 'E'; });
    expect(nodeE).toBeDefined();

    // Check edges
    expect(result.edges[0]).toEqual({ from: 'A', to: 'B' });
    expect(result.edges[1]).toEqual({ from: 'B', to: 'C' });
  });

  it('returns empty graph for empty or missing input', () => {
    expect(parseMermaidToGraph('')).toEqual({ nodes: [], edges: [] });
    expect(parseMermaidToGraph(null)).toEqual({ nodes: [], edges: [] });
    expect(parseMermaidToGraph(undefined)).toEqual({ nodes: [], edges: [] });
  });

  it('skips classDef and class lines', () => {
    var mermaid = [
      'graph TD',
      '    classDef high fill:#ff0000',
      '    class A high',
      '    A["Root"] --> B["Child"]',
    ].join('\n');

    var result = parseMermaidToGraph(mermaid);
    expect(result.nodes.length).toBe(2);
    expect(result.edges.length).toBe(1);
  });

  it('handles unquoted bracket labels', () => {
    var mermaid = 'graph TD\n    A[Root Node] --> B[Child Node]';
    var result = parseMermaidToGraph(mermaid);

    expect(result.nodes.length).toBe(2);
    var nodeA = result.nodes.find(function (n) { return n.id === 'A'; });
    expect(nodeA.label).toBe('Root Node');
  });

  it('handles parenthesis node patterns', () => {
    var mermaid = 'graph TD\n    A("Rounded Node") --> B(Simple Round)';
    var result = parseMermaidToGraph(mermaid);

    expect(result.nodes.length).toBe(2);
    var nodeA = result.nodes.find(function (n) { return n.id === 'A'; });
    expect(nodeA.label).toBe('Rounded Node');
    var nodeB = result.nodes.find(function (n) { return n.id === 'B'; });
    expect(nodeB.label).toBe('Simple Round');
  });

  it('creates nodes for IDs that only appear in edges', () => {
    var mermaid = 'graph TD\n    A --> B\n    B --> C';
    var result = parseMermaidToGraph(mermaid);

    expect(result.nodes.length).toBe(3);
    // Nodes without definitions get their ID as label
    var nodeA = result.nodes.find(function (n) { return n.id === 'A'; });
    expect(nodeA.label).toBe('A');
  });

  it('enriches node titles from attackSteps', () => {
    var mermaid = 'graph TD\n    A["Root"] --> B["Child"]';
    var steps = [
      { node_id: 'A', description: 'Full description of root' },
      { node_id: 'B', description: 'Full description of child' },
    ];

    var result = parseMermaidToGraph(mermaid, steps);

    var nodeA = result.nodes.find(function (n) { return n.id === 'A'; });
    expect(nodeA.title).toBe('Full description of root');
    var nodeB = result.nodes.find(function (n) { return n.id === 'B'; });
    expect(nodeB.title).toBe('Full description of child');
  });

  it('handles edge labels with pipe syntax', () => {
    var mermaid = 'graph TD\n    A --> |some label| B';
    var result = parseMermaidToGraph(mermaid);

    expect(result.edges.length).toBe(1);
    expect(result.edges[0]).toEqual({ from: 'A', to: 'B' });
  });
});

describe('graphToMermaid', () => {
  it('produces valid mermaid string from graph', () => {
    var graph = {
      nodes: [
        { id: 'A', label: 'Root Node' },
        { id: 'B', label: 'Child Node' },
      ],
      edges: [{ from: 'A', to: 'B' }],
    };

    var result = graphToMermaid(graph);
    expect(result).toContain('graph TD');
    expect(result).toContain('A["Root Node"]');
    expect(result).toContain('B["Child Node"]');
    expect(result).toContain('-->');
  });

  it('handles standalone nodes not in edges', () => {
    var graph = {
      nodes: [
        { id: 'A', label: 'Standalone' },
        { id: 'B', label: 'From' },
        { id: 'C', label: 'To' },
      ],
      edges: [{ from: 'B', to: 'C' }],
    };

    var result = graphToMermaid(graph);
    // Standalone node should appear as its own line
    var lines = result.split('\n');
    var standaloneLine = lines.find(function (l) { return l.includes('A["Standalone"]') && !l.includes('-->'); });
    expect(standaloneLine).toBeDefined();
  });

  it('handles null/undefined graph', () => {
    expect(graphToMermaid(null)).toBe('graph TD');
    expect(graphToMermaid(undefined)).toBe('graph TD');
  });

  it('handles empty graph', () => {
    var result = graphToMermaid({ nodes: [], edges: [] });
    expect(result).toBe('graph TD');
  });
});

describe('round-trip', () => {
  it('parse then print then parse produces equivalent graph', () => {
    var original = [
      'graph TD',
      '    A["Root"] --> B["Child 1"]',
      '    A["Root"] --> C["Child 2"]',
      '    B["Child 1"] --> D["Leaf"]',
    ].join('\n');

    var parsed1 = parseMermaidToGraph(original);
    var printed = graphToMermaid(parsed1);
    var parsed2 = parseMermaidToGraph(printed);

    // Same node IDs and labels
    var ids1 = parsed1.nodes.map(function (n) { return n.id; }).sort();
    var ids2 = parsed2.nodes.map(function (n) { return n.id; }).sort();
    expect(ids1).toEqual(ids2);

    var labels1 = parsed1.nodes.map(function (n) { return n.id + ':' + n.label; }).sort();
    var labels2 = parsed2.nodes.map(function (n) { return n.id + ':' + n.label; }).sort();
    expect(labels1).toEqual(labels2);

    // Same edges
    var edgeStr1 = parsed1.edges.map(function (e) { return e.from + '->' + e.to; }).sort();
    var edgeStr2 = parsed2.edges.map(function (e) { return e.from + '->' + e.to; }).sort();
    expect(edgeStr1).toEqual(edgeStr2);
  });
});
