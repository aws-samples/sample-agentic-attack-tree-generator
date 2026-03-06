import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, cleanup } from '@testing-library/react';
import AttackTreeViewer from '../src/components/AttackTreeViewer.jsx';

// Mock vis-network as it's loaded via CDN
function createMockVis() {
  const mockNetwork = {
    setData: vi.fn(),
    destroy: vi.fn(),
  };
  return {
    mockNetwork,
    vis: {
      DataSet: vi.fn((data) => data),
      Network: vi.fn(() => mockNetwork),
    },
  };
}

describe('AttackTreeViewer', () => {
  let originalVis;

  beforeEach(() => {
    originalVis = window.vis;
  });

  afterEach(() => {
    window.vis = originalVis;
    cleanup();
  });

  it('shows fallback message when vis-network is not available', () => {
    delete window.vis;
    render(<AttackTreeViewer graphData={{ nodes: [], edges: [] }} />);
    expect(screen.getByTestId('attack-tree-fallback')).toBeTruthy();
    expect(screen.getByText(/vis-network/i)).toBeTruthy();
  });

  it('renders the graph container when vis-network is available', () => {
    const { vis } = createMockVis();
    window.vis = vis;
    render(<AttackTreeViewer graphData={{ nodes: [{ id: '1', label: 'Root', title: '' }], edges: [] }} />);
    expect(screen.getByTestId('attack-tree-container')).toBeTruthy();
  });

  it('creates a vis.Network instance on mount with graph data', () => {
    const { vis, mockNetwork } = createMockVis();
    window.vis = vis;
    const graphData = {
      nodes: [{ id: 'A', label: 'Node A', title: 'Tooltip A' }],
      edges: [{ from: 'A', to: 'B' }],
    };
    render(<AttackTreeViewer graphData={graphData} />);
    expect(vis.Network).toHaveBeenCalledTimes(1);
    // First arg is the container DOM element
    expect(vis.Network.mock.calls[0][0]).toBeInstanceOf(HTMLElement);
  });

  it('destroys the network on unmount', () => {
    const { vis, mockNetwork } = createMockVis();
    window.vis = vis;
    const { unmount } = render(
      <AttackTreeViewer graphData={{ nodes: [], edges: [] }} />
    );
    unmount();
    expect(mockNetwork.destroy).toHaveBeenCalled();
  });

  it('applies default hierarchical layout options', () => {
    const { vis } = createMockVis();
    window.vis = vis;
    render(<AttackTreeViewer graphData={{ nodes: [], edges: [] }} />);
    const passedOptions = vis.Network.mock.calls[0][2];
    expect(passedOptions.layout.hierarchical.direction).toBe('UD');
    expect(passedOptions.physics).toBe(false);
  });

  it('merges custom options with defaults', () => {
    const { vis } = createMockVis();
    window.vis = vis;
    const customOptions = { physics: true };
    render(<AttackTreeViewer graphData={{ nodes: [], edges: [] }} options={customOptions} />);
    const passedOptions = vis.Network.mock.calls[0][2];
    expect(passedOptions.physics).toBe(true);
  });

  it('has minimum height of 600px on the container', () => {
    const { vis } = createMockVis();
    window.vis = vis;
    render(<AttackTreeViewer graphData={{ nodes: [], edges: [] }} />);
    const container = screen.getByTestId('attack-tree-container');
    expect(container.style.minHeight).toBe('600px');
  });

  it('has full width on the container', () => {
    const { vis } = createMockVis();
    window.vis = vis;
    render(<AttackTreeViewer graphData={{ nodes: [], edges: [] }} />);
    const container = screen.getByTestId('attack-tree-container');
    expect(container.style.width).toBe('100%');
  });

  it('handles null graphData gracefully', () => {
    const { vis } = createMockVis();
    window.vis = vis;
    render(<AttackTreeViewer graphData={null} />);
    expect(vis.Network).toHaveBeenCalledTimes(1);
    // Should pass empty arrays via DataSet
    expect(vis.DataSet).toHaveBeenCalledWith([]);
  });
});
