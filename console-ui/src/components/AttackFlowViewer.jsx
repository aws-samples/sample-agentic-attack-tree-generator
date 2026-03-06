import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  MiniMap,
  ReactFlowProvider,
  applyNodeChanges,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import ActionNode from './ActionNode';
import PropertiesPanel from './PropertiesPanel';
import { parseMermaidToGraph } from '../utils/mermaid-parser';
import { parseClassDefs, adaptToReactFlow } from '../utils/react-flow-adapter';

// Register the new Attack Flow-styled node type
const nodeTypes = { attackTreeNode: ActionNode };

/**
 * AttackFlowViewer — Attack Flow Builder-styled viewer with:
 * - Dark canvas with dot grid background
 * - Attack Flow-styled nodes (ActionNode)
 * - Docked right-side PropertiesPanel
 * - Click-to-select → properties update
 * - MiniMap for navigation
 */
export default function AttackFlowViewer({ attackTree, onFlowFieldChange }) {
  const wrapperRef = useRef(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [isDirty, setIsDirty] = useState(false);

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
      return { nodes: [], edges: [] };
    }
    const parserOutput = parseMermaidToGraph(attackTree.mermaid_code, attackTree.attack_steps);
    const classDefs = parseClassDefs(attackTree.mermaid_code);
    return adaptToReactFlow(parserOutput, attackTree, classDefs);
  }, [attackTree]);

  // Controlled state for nodes and edges
  const [nodes, setNodes] = useState(layoutNodes);
  const [edges, setEdges] = useState(layoutEdges);

  // Reset when attackTree prop changes
  useEffect(() => {
    setNodes(layoutNodes);
    setEdges(layoutEdges);
    setSelectedNode(null);
  }, [layoutNodes, layoutEdges]);

  // Handle node drag repositioning
  const onNodesChange = useCallback(
    (changes) => setNodes((nds) => applyNodeChanges(changes, nds)),
    []
  );

  // Handle node click — select for properties panel
  const handleNodeClick = useCallback((_event, node) => {
    if (node?.id && node?.data) {
      setSelectedNode(node.data);
    }
  }, []);

  // Handle canvas click — deselect node
  const handlePaneClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  // Debounced save for node edits — use refs to avoid stale closures
  const nodeSaveTimerRef = useRef(null);
  const flowSaveTimerRef = useRef(null);
  const selectedNodeRef = useRef(selectedNode);
  const attackTreeRef = useRef(attackTree);

  // Keep refs in sync with state
  useEffect(() => { selectedNodeRef.current = selectedNode; }, [selectedNode]);
  useEffect(() => { attackTreeRef.current = attackTree; }, [attackTree]);

  // Accumulated pending edits for the current node (batches multiple field changes)
  const pendingNodeEditsRef = useRef({});
  const pendingFlowEditsRef = useRef({});

  // Handle node property edits from the PropertiesPanel
  const handleNodeFieldChange = useCallback((field, value) => {
    if (!selectedNodeRef.current) return;
    const currentNodeId = selectedNodeRef.current.nodeId;
    const currentThreatId = attackTreeRef.current?.threat_id;
    setIsDirty(true);

    // Update the selected node state
    setSelectedNode(prev => prev ? { ...prev, [field]: value } : prev);

    // Update the ReactFlow node data for immediate visual feedback
    setNodes(nds =>
      nds.map(n => {
        if (n.data?.nodeId === currentNodeId) {
          return { ...n, data: { ...n.data, [field]: value } };
        }
        return n;
      })
    );

    // Accumulate this edit
    pendingNodeEditsRef.current[field] = value;

    // Debounced save to backend (1s after last edit)
    if (nodeSaveTimerRef.current) clearTimeout(nodeSaveTimerRef.current);
    nodeSaveTimerRef.current = setTimeout(() => {
      const fieldsToSave = { ...pendingNodeEditsRef.current };
      pendingNodeEditsRef.current = {};
      console.log('[AttackFlowViewer] Saving node edit:', { currentThreatId, currentNodeId, fieldsToSave });
      fetch('/api/test/node', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatId: currentThreatId,
          nodeId: currentNodeId,
          fields: fieldsToSave,
        }),
      })
        .then(r => r.json())
        .then(res => {
          console.log('[AttackFlowViewer] Node save response:', res);
          if (res.status === 'updated') {
            setIsDirty(false);
          }
        })
        .catch(err => console.error('Failed to save node edit:', err));
    }, 1000);
  }, []);

  // Handle flow-level property edits
  const handleFlowFieldChange = useCallback((field, value) => {
    const currentThreatId = attackTreeRef.current?.threat_id;
    setIsDirty(true);
    if (onFlowFieldChange) {
      onFlowFieldChange(field, value);
    }

    // Accumulate this edit
    pendingFlowEditsRef.current[field] = value;

    // Debounced save to backend (1s after last edit)
    if (flowSaveTimerRef.current) clearTimeout(flowSaveTimerRef.current);
    flowSaveTimerRef.current = setTimeout(() => {
      const fieldsToSave = { ...pendingFlowEditsRef.current };
      pendingFlowEditsRef.current = {};
      console.log('[AttackFlowViewer] Saving flow edit:', { currentThreatId, fieldsToSave });
      fetch('/api/test/flow', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatId: currentThreatId,
          fields: fieldsToSave,
        }),
      })
        .then(r => r.json())
        .then(res => {
          console.log('[AttackFlowViewer] Flow save response:', res);
          if (res.status === 'updated') {
            setIsDirty(false);
          }
        })
        .catch(err => console.error('Failed to save flow edit:', err));
    }, 1000);
  }, [onFlowFieldChange]);

  // Empty state
  if (!attackTree || !attackTree.mermaid_code || layoutNodes.length === 0) {
    return (
      <Box textAlign="center" padding="l" color="text-body-secondary">
        No graph data available
      </Box>
    );
  }

  return (
    <div ref={wrapperRef} style={{
      position: 'relative',
      display: 'flex',
      background: isFullscreen ? '#1a1a2e' : 'transparent',
      height: isFullscreen ? '100vh' : 'calc(100vh - 380px)',
      minHeight: 550,
    }}>
      {/* Canvas area */}
      <div style={{
        flex: 1,
        position: 'relative',
        borderRadius: isFullscreen ? 0 : '8px 0 0 8px',
        overflow: 'hidden',
      }}>
        {/* Toolbar */}
        <div style={{
          position: 'absolute',
          top: 8,
          right: 8,
          zIndex: 10,
          display: 'flex',
          gap: 6,
        }}>
          <Button
            iconName={isFullscreen ? 'shrink' : 'expand'}
            variant="normal"
            onClick={toggleFullscreen}
          >
            {isFullscreen ? 'Exit' : 'Fullscreen'}
          </Button>
        </div>

        <ReactFlowProvider>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onNodeClick={handleNodeClick}
            onPaneClick={handlePaneClick}
            nodesDraggable={true}
            fitView
            style={{ background: '#1a1a2e' }}
          >
            <Background variant="dots" gap={20} size={1} color="#333355" />
            <Controls
              style={{ background: '#2a2a4a', borderColor: '#444466' }}
            />
            <MiniMap
              nodeStrokeWidth={3}
              style={{
                background: '#16162a',
                border: '1px solid #333355',
              }}
              nodeColor={(n) => {
                const cat = n.data?.category;
                if (cat === 'attack') return '#B71C1C';
                if (cat === 'goal') return '#E65100';
                if (cat === 'fact') return '#1565C0';
                if (cat === 'mitigation') return '#2E7D32';
                return '#37474F';
              }}
            />
          </ReactFlow>
        </ReactFlowProvider>

        {/* Status bar */}
        <div style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          background: 'rgba(26,26,46,0.9)',
          borderTop: '1px solid #333355',
          padding: '4px 12px',
          display: 'flex',
          gap: 16,
          fontSize: 11,
          color: '#8888aa',
          fontFamily: '"Amazon Ember", "Helvetica Neue", Roboto, Arial, sans-serif',
        }}>
          <span>{nodes.length} nodes</span>
          <span>{edges.length} edges</span>
          <span>{selectedNode ? `Selected: ${selectedNode.label || selectedNode.nodeId}` : 'No selection'}</span>
          {isDirty && <span style={{ color: '#42A5F5' }}>● Modified</span>}
        </div>
      </div>

      {/* Properties Panel — docked right */}
      <PropertiesPanel
        selectedNode={selectedNode}
        attackTree={attackTree}
        onFlowFieldChange={handleFlowFieldChange}
        onNodeFieldChange={handleNodeFieldChange}
        isDirty={isDirty}
      />
    </div>
  );
}