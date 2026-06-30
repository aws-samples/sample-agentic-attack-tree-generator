'use client';

/**
 * TS/Next port of console-ui's ReactFlowAttackTreeViewer.jsx.
 *
 * Dagre-laid-out attack tree rendered with @xyflow/react. Nodes are draggable,
 * clicks are forwarded to the parent, and a fullscreen toggle is provided.
 */

import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import {
  ReactFlow,
  Controls,
  ReactFlowProvider,
  applyNodeChanges,
  type NodeChange,
  type NodeMouseHandler,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import AttackTreeNode from './AttackTreeNode';
import { parseMermaidToGraph } from '@/utils/mermaid-parser';
import {
  parseClassDefs,
  adaptToReactFlow,
  type AttackTreeFlowNode,
  type AttackTreeNodeData,
} from '@/utils/react-flow-adapter';
import type { ReportAttackTree } from '@/utils/mitigation-aggregator';

// Defined outside the component to avoid React Flow re-registering node types on every render
const nodeTypes = { attackTreeNode: AttackTreeNode };

/** Attack tree bundle with the mermaid source string the viewer renders. */
type ViewerAttackTree = ReportAttackTree & { mermaid_code?: string };

export interface ReactFlowAttackTreeViewerProps {
  attackTree: ViewerAttackTree | null | undefined;
  onNodeClick?: (nodeId: string, data: AttackTreeNodeData) => void;
}

export default function ReactFlowAttackTreeViewer({
  attackTree,
  onNodeClick,
}: ReactFlowAttackTreeViewerProps) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Sync fullscreen state with browser API
  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  const toggleFullscreen = useCallback(() => {
    if (!wrapperRef.current) return;
    if (!document.fullscreenElement) {
      wrapperRef.current.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  }, []);

  // Compute the dagre-laid-out nodes/edges from the attack tree data
  const { nodes: layoutNodes, edges: layoutEdges } = useMemo(() => {
    if (!attackTree || !attackTree.mermaid_code) {
      return { nodes: [] as AttackTreeFlowNode[], edges: [] };
    }
    const parserOutput = parseMermaidToGraph(attackTree.mermaid_code, attackTree.attack_steps);
    const classDefs = parseClassDefs(attackTree.mermaid_code);
    return adaptToReactFlow(parserOutput, attackTree, classDefs);
  }, [attackTree]);

  // Controlled state for nodes and edges — allows drag repositioning to persist
  const [nodes, setNodes] = useState(layoutNodes);
  const [edges, setEdges] = useState(layoutEdges);

  // Reset nodes/edges when the attackTree prop changes (new threat selected)
  useEffect(() => {
    setNodes(layoutNodes);
    setEdges(layoutEdges);
  }, [layoutNodes, layoutEdges]);

  // Handle node position changes (drag) using @xyflow/react's applyNodeChanges
  const onNodesChange = useCallback(
    (changes: NodeChange<AttackTreeFlowNode>[]) =>
      setNodes((nds) => applyNodeChanges(changes, nds)),
    [],
  );

  // Forward node clicks to parent callback with nodeId and node data
  const handleNodeClick = useCallback<NodeMouseHandler<AttackTreeFlowNode>>(
    (_event, node) => {
      if (onNodeClick && node?.id && node?.data) {
        onNodeClick(node.id, node.data);
      }
    },
    [onNodeClick],
  );

  // Empty state
  if (!attackTree || !attackTree.mermaid_code || nodes.length === 0) {
    return (
      <Box textAlign="center" padding="l" color="text-body-secondary">
        No graph data available
      </Box>
    );
  }

  return (
    <div ref={wrapperRef} style={{ position: 'relative', background: isFullscreen ? '#fff' : 'transparent' }}>
      <div style={{ position: 'absolute', top: '8px', right: '8px', zIndex: 10 }}>
        <Button iconName={isFullscreen ? 'shrink' : 'expand'} variant="normal" onClick={toggleFullscreen}>
          {isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
        </Button>
      </div>
      <div style={{
        height: isFullscreen ? '100vh' : 'calc(100vh - 420px)',
        minHeight: '500px',
        width: '100%',
        border: isFullscreen ? 'none' : '1px solid #e9ebed',
        borderRadius: isFullscreen ? '0' : '8px',
        background: '#fff',
      }}>
        <ReactFlowProvider>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onNodeClick={handleNodeClick}
            nodesDraggable={true}
            fitView
          >
            <Controls />
          </ReactFlow>
        </ReactFlowProvider>
      </div>
    </div>
  );
}
