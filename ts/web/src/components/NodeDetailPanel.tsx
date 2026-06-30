'use client';

/**
 * TS/Next port of console-ui's NodeDetailPanel.jsx.
 *
 * An absolutely-positioned card that displays node details (description, MITRE
 * mappings, mitigations) with an independent close button. Reuses
 * {@link NodePopoverContent} from AttackTreeNode for the body.
 */

import Button from '@cloudscape-design/components/button';
import { NodePopoverContent } from './AttackTreeNode';
import type { AttackTreeNodeData } from '@/utils/react-flow-adapter';

export interface NodeDetailPanelProps {
  /** Node data (label, nodeId, description, ttcMappings, mitigations). */
  data?: Partial<AttackTreeNodeData> | null;
  /** Top-left position for the panel. */
  position?: { x: number; y: number } | null;
  /** Called when the close button is clicked. */
  onClose: () => void;
  /** Stack order for the panel. */
  zIndex?: number;
}

export default function NodeDetailPanel({ data, position, onClose, zIndex }: NodeDetailPanelProps) {
  return (
    <div
      data-testid="node-detail-panel"
      style={{
        position: 'absolute',
        top: position?.y ?? 0,
        left: position?.x ?? 0,
        zIndex: zIndex ?? 1000,
        width: 380,
        maxHeight: 520,
        overflowY: 'auto',
        background: '#ffffff',
        borderRadius: '12px',
        border: '1px solid #d5dbdb',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.15)',
        padding: '16px',
        fontFamily: '"Amazon Ember", "Helvetica Neue", Roboto, Arial, sans-serif',
      }}
    >
      {/* Close button row */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '8px' }}>
        <Button
          iconName="close"
          variant="icon"
          ariaLabel="Close panel"
          onClick={onClose}
          data-testid="node-detail-panel-close"
        />
      </div>

      {/* Reuse the existing popover content */}
      <NodePopoverContent data={data} />
    </div>
  );
}
