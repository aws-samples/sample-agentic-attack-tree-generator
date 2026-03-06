import { describe, it, expect, vi, afterEach } from 'vitest';
import React from 'react';
import { render, screen, cleanup } from '@testing-library/react';
import ReactFlowAttackTreeViewer from '../src/components/ReactFlowAttackTreeViewer.jsx';

// Mock @xyflow/react to inspect props passed to ReactFlow
const mockReactFlow = vi.fn(({ children }) => <div data-testid="react-flow">{children}</div>);
const mockApplyNodeChanges = vi.fn((changes, nodes) => nodes);

vi.mock('@xyflow/react', () => ({
  ReactFlow: (props) => {
    mockReactFlow(props);
    return <div data-testid="react-flow">{props.children}</div>;
  },
  ReactFlowProvider: ({ children }) => <div>{children}</div>,
  Controls: () => <div data-testid="controls" />,
  applyNodeChanges: (...args) => mockApplyNodeChanges(...args),
}));

// Mock the mermaid parser and react-flow-adapter
vi.mock('../src/utils/mermaid-parser', () => ({
  parseMermaidToGraph: vi.fn(() => ({
    nodes: [
      { id: 'A', label: 'Root Goal', title: '' },
      { id: 'B', label: 'Attack Step 1', title: '' },
    ],
    edges: [{ from: 'A', to: 'B' }],
  })),
}));

vi.mock('../src/utils/react-flow-adapter', () => ({
  parseClassDefs: vi.fn(() => ({ A: 'goal', B: 'attack' })),
  adaptToReactFlow: vi.fn(() => ({
    nodes: [
      { id: 'A', type: 'attackTreeNode', position: { x: 0, y: 0 }, data: { label: 'Root Goal' } },
      { id: 'B', type: 'attackTreeNode', position: { x: 0, y: 100 }, data: { label: 'Attack Step 1' } },
    ],
    edges: [
      { id: 'A->B', source: 'A', target: 'B' },
    ],
  })),
}));

const sampleAttackTree = {
  mermaid_code: 'graph TD\nA[Root Goal] --> B[Attack Step 1]',
  attack_steps: [
    { node_id: 'A', description: 'Root Goal' },
    { node_id: 'B', description: 'Attack Step 1' },
  ],
  ttc_mappings: [],
  mitigations: [],
};

describe('ReactFlowAttackTreeViewer', () => {
  afterEach(() => {
    cleanup();
    mockReactFlow.mockClear();
    mockApplyNodeChanges.mockClear();
  });

  it('renders empty state when attackTree is null', () => {
    render(<ReactFlowAttackTreeViewer attackTree={null} />);
    expect(screen.getByText('No graph data available')).toBeTruthy();
  });

  it('renders empty state when attackTree has no mermaid_code', () => {
    render(<ReactFlowAttackTreeViewer attackTree={{ attack_steps: [] }} />);
    expect(screen.getByText('No graph data available')).toBeTruthy();
  });

  it('renders ReactFlow when valid attackTree is provided', () => {
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} />);
    expect(screen.getByTestId('react-flow')).toBeTruthy();
  });

  it('passes nodesDraggable={true} to ReactFlow', () => {
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    expect(lastCall.nodesDraggable).toBe(true);
  });

  it('passes onNodesChange handler to ReactFlow', () => {
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    expect(typeof lastCall.onNodesChange).toBe('function');
  });

  it('passes nodes and edges arrays to ReactFlow', () => {
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    expect(Array.isArray(lastCall.nodes)).toBe(true);
    expect(Array.isArray(lastCall.edges)).toBe(true);
    expect(lastCall.nodes.length).toBe(2);
    expect(lastCall.edges.length).toBe(1);
  });

  it('onNodesChange calls applyNodeChanges to update node positions', () => {
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    const changes = [{ type: 'position', id: 'A', position: { x: 50, y: 50 } }];
    lastCall.onNodesChange(changes);
    expect(mockApplyNodeChanges).toHaveBeenCalledWith(changes, expect.any(Array));
  });

  it('passes onNodeClick handler to ReactFlow', () => {
    const onNodeClick = vi.fn();
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} onNodeClick={onNodeClick} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    expect(typeof lastCall.onNodeClick).toBe('function');
  });

  it('onNodeClick forwards node id and data to parent callback', () => {
    const onNodeClick = vi.fn();
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} onNodeClick={onNodeClick} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    // Simulate ReactFlow calling onNodeClick with event and node object
    const fakeEvent = {};
    const fakeNode = { id: 'A', data: { label: 'Root Goal', description: 'test' } };
    lastCall.onNodeClick(fakeEvent, fakeNode);
    expect(onNodeClick).toHaveBeenCalledWith('A', { label: 'Root Goal', description: 'test' });
  });

  it('onNodeClick does not call parent when node has no id', () => {
    const onNodeClick = vi.fn();
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} onNodeClick={onNodeClick} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    lastCall.onNodeClick({}, { data: { label: 'test' } });
    expect(onNodeClick).not.toHaveBeenCalled();
  });

  it('onNodeClick does not call parent when node has no data', () => {
    const onNodeClick = vi.fn();
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} onNodeClick={onNodeClick} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    lastCall.onNodeClick({}, { id: 'A' });
    expect(onNodeClick).not.toHaveBeenCalled();
  });

  it('onNodeClick is safe when no callback is provided', () => {
    render(<ReactFlowAttackTreeViewer attackTree={sampleAttackTree} />);
    const lastCall = mockReactFlow.mock.calls[mockReactFlow.mock.calls.length - 1][0];
    // Should not throw when no onNodeClick prop is passed
    expect(() => {
      lastCall.onNodeClick({}, { id: 'A', data: { label: 'Root Goal' } });
    }).not.toThrow();
  });
});
