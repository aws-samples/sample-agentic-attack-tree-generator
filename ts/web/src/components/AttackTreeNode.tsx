'use client';

/**
 * TS/Next port of console-ui's AttackTreeNode.jsx.
 *
 * Two exports kept faithful to the original:
 *   - `NodePopoverContent` — the Cloudscape detail body reused by NodeDetailPanel
 *   - default `AttackTreeNode` — the compact React Flow node renderer
 *
 * The node `data` payload is the enriched {@link AttackTreeNodeData} produced by
 * the react-flow-adapter (camelCase: nodeId, ttcMappings, reachProbability, …).
 */

import { Handle, Position } from '@xyflow/react';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import Link from '@cloudscape-design/components/link';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import { buildTechniqueUrl } from '@/utils/technique-url';
import type { AttackTreeNodeData } from '@/utils/react-flow-adapter';
import type { RawMitigation } from '@/utils/mitigation-aggregator';

/**
 * A matched ttc_mapping as it appears on a node (reasoning already stripped).
 *
 * Stated explicitly rather than as `Omit<RawTtcMapping, 'reasoning'>`:
 * `RawTtcMapping` carries a `[key: string]: unknown` index signature, and
 * `Omit` over an indexed type collapses its named members to `unknown`. These
 * are the fields this component actually reads, with their real types.
 */
interface NodeTtcMapping {
  attack_step?: string;
  technique_id?: string;
  technique_name?: string;
  confidence?: number;
  tactics?: string[];
  mitigations?: RawMitigation[] | null;
}

/**
 * Precise node-data shape these renderers read. Mirrors the subset of
 * {@link AttackTreeNodeData} consumed here, but with `ttcMappings` typed as the
 * precise {@link NodeTtcMapping}[] (see note above) instead of the index-poisoned
 * `Omit<RawTtcMapping, 'reasoning'>[]`.
 */
interface NodeData {
  label?: string;
  nodeId?: string;
  category?: string;
  description?: string;
  ttcMappings?: NodeTtcMapping[];
  mitigations?: RawMitigation[];
  probability?: number | null;
  reachProbability?: number | null;
  probabilityRationale?: string;
}

interface CategoryColor {
  bg: string;
  border: string;
  text: string;
}

const CATEGORY_COLORS: Record<string, CategoryColor> = {
  attack: { bg: '#fef2f2', border: '#dc2626', text: '#991b1b' },
  goal: { bg: '#fff7ed', border: '#ea580c', text: '#9a3412' },
  fact: { bg: '#eff6ff', border: '#2563eb', text: '#1e40af' },
  mitigation: { bg: '#f0fdf4', border: '#16a34a', text: '#166534' },
  default: { bg: '#f9fafb', border: '#6b7280', text: '#374151' },
};

function formatConfidence(score: number | null | undefined): string {
  if (typeof score !== 'number' || isNaN(score)) return '0%';
  return Math.round(score * 100) + '%';
}

function collectAllTactics(ttcMappings: NodeTtcMapping[] | null | undefined): string[] {
  const set = new Set<string>();
  (ttcMappings || []).forEach((m) => (m.tactics || []).forEach((t) => set.add(t)));
  return [...set];
}

interface ProbabilityBadgeColors {
  bg: string;
  fg: string;
}

function probabilityBadgeColors(reach: number | null | undefined): ProbabilityBadgeColors | null {
  if (typeof reach !== 'number' || isNaN(reach)) return null;
  if (reach >= 0.5) return { bg: '#fef2f2', fg: '#991b1b' }; // red
  if (reach >= 0.2) return { bg: '#fff7ed', fg: '#9a3412' }; // amber
  return { bg: '#f0fdf4', fg: '#166534' }; // green
}

function formatProbability(p: number | null | undefined): string {
  if (typeof p !== 'number' || isNaN(p)) return '—';
  return Math.round(p * 100) + '%';
}

export interface NodePopoverContentProps {
  data?: NodeData | null;
}

export function NodePopoverContent({ data }: NodePopoverContentProps) {
  const { label, nodeId, description, ttcMappings = [], mitigations = [] } = data || {};
  const probability = typeof data?.probability === 'number' ? data.probability : null;
  const reachProbability = typeof data?.reachProbability === 'number' ? data.reachProbability : null;
  const probabilityRationale = data?.probabilityRationale || '';
  const hasProbability = probability !== null || reachProbability !== null;
  const hasDescription = Boolean(description && description.length > 0);
  const hasMappings = Boolean(ttcMappings && ttcMappings.length > 0);
  const hasMitigations = Boolean(mitigations && mitigations.length > 0);
  const hasAnyDetails = hasDescription || hasMappings || hasMitigations;
  const allTactics = collectAllTactics(ttcMappings);

  return (
    <SpaceBetween size="m">
      {/* Header: label + node ID, tactics top-right */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
        <div>
          <Box variant="h4">{label}</Box>
          <Box variant="small" color="text-body-secondary">{nodeId}</Box>
        </div>
        {allTactics.length > 0 && (
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
            {allTactics.map((t, i) => <Badge key={i} color="blue">{t}</Badge>)}
          </div>
        )}
      </div>

      {/* Description */}
      {hasDescription && (
        <div>
          <Box variant="awsui-key-label">Description</Box>
          <Box variant="p">{description}</Box>
        </div>
      )}

      {/* Likelihood — step probability + cumulative reach probability */}
      {hasProbability && (
        <div>
          <Box variant="awsui-key-label">Likelihood</Box>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', fontSize: '13px' }}>
            <div>
              <Box variant="small" color="text-body-secondary">Step</Box>
              <Box variant="p">{formatProbability(probability)}</Box>
            </div>
            <div>
              <Box variant="small" color="text-body-secondary">Reach (cumulative)</Box>
              <Box variant="p">{formatProbability(reachProbability)}</Box>
            </div>
          </div>
          {probabilityRationale && (
            <Box variant="small" color="text-body-secondary" margin={{ top: 'xs' }}>
              {probabilityRationale}
            </Box>
          )}
        </div>
      )}

      {/* TTP Mappings — no duplicate tactics, no reasoning/embedding text */}
      {hasMappings && (
        <ExpandableSection headerText={`TTP Mappings (${ttcMappings!.length})`} defaultExpanded>
          <SpaceBetween size="s">
            {ttcMappings!.map((mapping, idx) => {
              const url = buildTechniqueUrl(mapping.technique_id);
              return (
                <div key={mapping.technique_id || idx} style={{ padding: '10px 12px', background: '#f2f3f3', borderRadius: '8px', border: '1px solid #eaeded' }}>
                  <div style={{ fontWeight: 600, fontSize: '13px' }}>
                    {url ? (
                      <Link href={url} external fontSize="body-s">{mapping.technique_id} — {mapping.technique_name}</Link>
                    ) : (
                      <span>{mapping.technique_id} — {mapping.technique_name}</span>
                    )}
                  </div>
                  <Box variant="small" color="text-body-secondary" margin={{ top: 'xxs' }}>
                    Confidence: {formatConfidence(mapping.confidence)}
                  </Box>
                </div>
              );
            })}
          </SpaceBetween>
        </ExpandableSection>
      )}

      {/* Mitigations — title-only list. Full implementation guidance lives on
          the per-threat mitigations table; the side panel stays scannable. */}
      {hasMitigations && (
        <ExpandableSection headerText={`🛡️ Mitigations (${mitigations!.length})`} defaultExpanded={false}>
          <ul style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {mitigations!.map((mit, idx) => (
              <li key={idx} style={{ fontSize: '13px' }}>
                {mit.name || mit.mitigation || `Mitigation ${idx + 1}`}
              </li>
            ))}
          </ul>
        </ExpandableSection>
      )}

      {!hasAnyDetails && <Box variant="p" color="text-body-secondary">No additional details available</Box>}
    </SpaceBetween>
  );
}

export interface AttackTreeNodeProps {
  data?: NodeData | null;
}

export default function AttackTreeNode({ data }: AttackTreeNodeProps) {
  const category = data?.category || 'default';
  const colors = CATEGORY_COLORS[category] || CATEGORY_COLORS.default!;
  const allTactics = collectAllTactics(data?.ttcMappings);
  const reach = data?.reachProbability;
  const badgeColors = probabilityBadgeColors(reach);

  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div
        style={{
          padding: '8px 16px', border: `2px solid ${colors.border}`, backgroundColor: colors.bg,
          borderRadius: '8px', fontFamily: '"Amazon Ember", "Helvetica Neue", Roboto, Arial, sans-serif',
          fontSize: '13px', color: colors.text, maxWidth: '250px', cursor: 'pointer',
          transition: 'box-shadow 0.15s ease',
        }}
        onMouseEnter={(e) => { e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '6px' }}>
          <div style={{ flex: 1 }}>{data?.label}</div>
          {badgeColors && category !== 'fact' && (
            <span style={{
              fontSize: '10px', fontWeight: 700, padding: '1px 6px', borderRadius: '4px',
              background: badgeColors.bg, color: badgeColors.fg, whiteSpace: 'nowrap',
            }}>
              {formatProbability(reach)}
            </span>
          )}
        </div>
        {allTactics.length > 0 && (
          <div style={{ display: 'flex', gap: '3px', flexWrap: 'wrap', marginTop: '4px' }}>
            {allTactics.map((t, i) => (
              <span key={i} style={{ fontSize: '9px', padding: '1px 5px', borderRadius: '3px', background: 'rgba(0,0,0,0.08)', color: colors.text, fontWeight: 600 }}>{t}</span>
            ))}
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}

export { CATEGORY_COLORS };
export type { NodeTtcMapping, RawMitigation };
