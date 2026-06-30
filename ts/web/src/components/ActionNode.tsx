'use client';

/**
 * TS/Next port of console-ui's ActionNode.jsx.
 *
 * Attack Flow Builder-styled action node: technique ID + tactic in a coloured
 * header, action name + footer (technique id, mitigation count) in a white body.
 */

import { Handle, Position } from '@xyflow/react';
import type { CSSProperties } from 'react';
import type { RawMitigation } from '@/utils/mitigation-aggregator';

/**
 * Precise node-data shape this renderer reads.
 *
 * We do NOT derive from `AttackTreeNodeData`: that type carries a
 * `[key: string]: unknown` index signature (and its `ttcMappings` is
 * `Omit<RawTtcMapping, 'reasoning'>[]`, whose own index signature collapses
 * the named members to `unknown`). Re-stating the handful of fields used here
 * with their real types lets member access type-check without `any`.
 */
interface NodeTtcMapping {
  technique_id?: string;
  tactics?: string[];
}

interface ActionNodeData {
  label?: string;
  category?: string;
  ttcMappings?: NodeTtcMapping[];
  mitigations?: RawMitigation[];
}

const CATEGORY_HEADER_COLORS: Record<string, string> = {
  attack: '#B71C1C',
  goal: '#E65100',
  fact: '#1565C0',
  mitigation: '#2E7D32',
  technique: '#4A148C',
  default: '#37474F',
};

export interface ActionNodeProps {
  data?: ActionNodeData | null;
  selected?: boolean;
}

export default function ActionNode({ data, selected }: ActionNodeProps) {
  const category = data?.category || 'default';
  const headerBg = CATEGORY_HEADER_COLORS[category] || CATEGORY_HEADER_COLORS.default!;
  const techniqueId = data?.ttcMappings?.[0]?.technique_id || '';
  const tacticName = data?.ttcMappings?.[0]?.tactics?.[0] || '';
  const mitigationCount = data?.mitigations?.length || 0;

  return (
    <>
      <Handle type="target" position={Position.Top} style={{ background: '#555' }} />
      <div
        data-testid="action-node"
        style={{
          width: 260,
          borderRadius: 6,
          border: selected ? '2px solid #42A5F5' : '1px solid #424242',
          overflow: 'hidden',
          boxShadow: selected
            ? '0 0 0 2px rgba(66,165,245,0.3)'
            : '0 1px 4px rgba(0,0,0,0.25)',
          cursor: 'pointer',
          transition: 'box-shadow 0.15s ease, border-color 0.15s ease',
        }}
      >
        {/* Header — category + tactic */}
        <div style={{
          background: headerBg,
          color: '#fff',
          padding: '5px 10px',
          fontSize: 10,
          fontWeight: 600,
          fontFamily: '"Amazon Ember", "Helvetica Neue", Roboto, Arial, sans-serif',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          minHeight: 24,
          textTransform: 'uppercase',
          letterSpacing: '0.3px',
        }}>
          <span>{category || 'default'}</span>
          {tacticName && (
            <span style={{ opacity: 0.85, fontWeight: 400, fontSize: 9 }}>
              {tacticName}
            </span>
          )}
        </div>

        {/* Body — action name only (no duplicated description) */}
        <div style={{
          background: '#fff',
          padding: '8px 10px',
          fontFamily: '"Amazon Ember", "Helvetica Neue", Roboto, Arial, sans-serif',
        }}>
          <div style={{
            fontWeight: 600,
            fontSize: 12,
            color: '#1a1a1a',
            lineHeight: '16px',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            display: '-webkit-box',
            WebkitLineClamp: 4,
            WebkitBoxOrient: 'vertical',
            wordBreak: 'break-word',
          } as CSSProperties}>
            {data?.label || 'Unnamed'}
          </div>
          {/* Footer — technique ID (bottom-left) + mitigation count (bottom-right) */}
          {(techniqueId || mitigationCount > 0) && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 5 }}>
              <span style={{
                fontSize: 9, color: '#888', fontWeight: 500,
              }}>
                {techniqueId}
              </span>
              {mitigationCount > 0 && (
                <span style={{
                  fontSize: 9, padding: '1px 5px', borderRadius: 3,
                  background: '#E8F5E9', color: '#2E7D32', fontWeight: 600,
                  border: '1px solid #C8E6C9',
                }}>
                  🛡️ {mitigationCount}
                </span>
              )}
            </div>
          )}
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: '#555' }} />
    </>
  );
}
