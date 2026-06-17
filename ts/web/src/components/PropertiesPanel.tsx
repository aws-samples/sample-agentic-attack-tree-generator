'use client';

/**
 * TS/Next port of console-ui's PropertiesPanel.jsx.
 *
 * Docked right-side panel emulating the Attack Flow Builder's Properties pane.
 * Context-sensitive: shows flow properties when no node is selected, node
 * properties when a node is selected.
 */

import SpaceBetween from '@cloudscape-design/components/space-between';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Textarea from '@cloudscape-design/components/textarea';
import Select from '@cloudscape-design/components/select';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Link from '@cloudscape-design/components/link';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import type { BadgeProps } from '@cloudscape-design/components/badge';
import { buildTechniqueUrl } from '@/utils/technique-url';
import type { ReportAttackTree, RawMitigation } from '@/utils/mitigation-aggregator';

/** Field keys editable on the flow-level (threat) properties form. */
type FlowField = 'threat_statement' | 'threat_category' | 'priority';
/** Field keys editable on the node-level properties form. */
type NodeField = 'label' | 'description';

/**
 * A matched ttc_mapping as read by this panel.
 *
 * Stated explicitly rather than reused from `AttackTreeNodeData.ttcMappings`
 * (`Omit<RawTtcMapping, 'reasoning'>[]`): `RawTtcMapping` has a
 * `[key: string]: unknown` index signature, and `Omit` over an indexed type
 * collapses its named members to `unknown`. These are the fields used here,
 * with their real types.
 */
interface NodeTtcMapping {
  technique_id?: string;
  technique_name?: string;
  confidence?: number;
  tactics?: string[];
}

/** Precise node-data shape this panel reads (see {@link NodeTtcMapping}). */
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

interface FlowPropertiesProps {
  attackTree?: ReportAttackTree | null;
  onFieldChange: (field: FlowField, value: string) => void;
}

/**
 * Flow-level properties shown when no node is selected.
 */
function FlowProperties({ attackTree, onFieldChange }: FlowPropertiesProps) {
  if (!attackTree) return null;
  const priority = attackTree.priority != null ? String(attackTree.priority) : '';
  return (
    <SpaceBetween size="m">
      <FormField label="Threat ID">
        <Input value={attackTree.threat_id || ''} readOnly disabled />
      </FormField>
      <FormField label="Threat Statement">
        <Textarea
          value={attackTree.threat_statement || ''}
          onChange={({ detail }) => onFieldChange('threat_statement', detail.value)}
          rows={3}
        />
      </FormField>
      <FormField label="Category">
        <Input
          value={attackTree.threat_category || ''}
          onChange={({ detail }) => onFieldChange('threat_category', detail.value)}
        />
      </FormField>
      <FormField label="Priority">
        <Select
          selectedOption={priority ? { label: priority, value: priority } : null}
          onChange={({ detail }) => onFieldChange('priority', detail.selectedOption.value ?? '')}
          options={[
            { label: 'High', value: 'High' },
            { label: 'Medium', value: 'Medium' },
            { label: 'Low', value: 'Low' },
          ]}
          placeholder="Select priority"
        />
      </FormField>
    </SpaceBetween>
  );
}

function formatProbability(p: number | null | undefined): string {
  if (typeof p !== 'number' || isNaN(p)) return '—';
  return Math.round(p * 100) + '%';
}

function probabilityColor(reach: number | null | undefined): BadgeProps['color'] {
  if (typeof reach !== 'number' || isNaN(reach)) return 'grey';
  if (reach >= 0.5) return 'red';
  if (reach >= 0.2) return 'grey';
  return 'green';
}

interface NodePropertiesProps {
  nodeData?: NodeData | null;
  onNodeFieldChange: (field: NodeField, value: string) => void;
}

/**
 * Node-level properties shown when a node is selected.
 */
function NodeProperties({ nodeData, onNodeFieldChange }: NodePropertiesProps) {
  if (!nodeData) return null;

  const {
    label, nodeId, category, description, ttcMappings = [], mitigations = [],
    probability, reachProbability, probabilityRationale,
  } = nodeData;

  const categoryColor: BadgeProps['color'] =
    category === 'attack' ? 'red' :
    category === 'goal' ? 'red' :
    category === 'fact' ? 'blue' :
    category === 'mitigation' ? 'green' : 'grey';

  return (
    <SpaceBetween size="s">
      {/* Basic info */}
      <FormField label="Node ID">
        <Input value={nodeId || ''} readOnly disabled />
      </FormField>
      <FormField label="Label">
        <Input
          value={label || ''}
          onChange={({ detail }) => onNodeFieldChange('label', detail.value)}
        />
      </FormField>
      <FormField label="Category">
        <Box>
          <Badge color={categoryColor}>
            {category || 'default'}
          </Badge>
        </Box>
      </FormField>
      <FormField label="Description">
        <Textarea
          value={description || ''}
          onChange={({ detail }) => onNodeFieldChange('description', detail.value)}
          rows={3}
        />
      </FormField>

      {/* Likelihood */}
      {category !== 'fact' && (typeof probability === 'number' || typeof reachProbability === 'number') && (
        <ExpandableSection headerText="Likelihood" defaultExpanded>
          <SpaceBetween size="xs">
            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
              <div>
                <Box variant="awsui-key-label" fontSize="body-s">Step</Box>
                <Badge color={probabilityColor(probability)}>{formatProbability(probability)}</Badge>
              </div>
              <div>
                <Box variant="awsui-key-label" fontSize="body-s">Reach (cumulative)</Box>
                <Badge color={probabilityColor(reachProbability)}>{formatProbability(reachProbability)}</Badge>
              </div>
            </div>
            {probabilityRationale && (
              <Box variant="small" color="text-body-secondary">
                {probabilityRationale}
              </Box>
            )}
          </SpaceBetween>
        </ExpandableSection>
      )}

      {/* TTP Mappings */}
      {ttcMappings.length > 0 && (
        <ExpandableSection
          headerText={`TTP Mappings (${ttcMappings.length})`}
          defaultExpanded
        >
          <SpaceBetween size="s">
            {ttcMappings.map((mapping, idx) => {
              const url = buildTechniqueUrl(mapping.technique_id);
              return (
                <div key={mapping.technique_id || idx} style={{
                  padding: '8px 10px',
                  background: '#f8f8f8',
                  borderRadius: 6,
                  border: '1px solid #e9ebed',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>
                      {url ? (
                        <Link href={url} external fontSize="body-s">
                          {mapping.technique_id}
                        </Link>
                      ) : (
                        <span>{mapping.technique_id}</span>
                      )}
                      <span style={{ fontWeight: 400, marginLeft: 6, color: '#555' }}>
                        {mapping.technique_name}
                      </span>
                    </div>
                    <Badge color="blue">
                      {Math.round((mapping.confidence || 0) * 100)}%
                    </Badge>
                  </div>
                  {mapping.tactics && mapping.tactics.length > 0 && (
                    <div style={{ display: 'flex', gap: 4, marginTop: 4, flexWrap: 'wrap' }}>
                      {mapping.tactics.map((t, i) => (
                        <span key={i} style={{
                          fontSize: 10, padding: '1px 6px', borderRadius: 3,
                          background: '#E3F2FD', color: '#1565C0', fontWeight: 500,
                        }}>
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </SpaceBetween>
        </ExpandableSection>
      )}

      {/* Mitigations — title-only summary. The full implementation guidance
          lives in the mitigations table below the attack tree, so the side
          panel stays scannable. */}
      <ExpandableSection
        headerText={`🛡️ Mitigations (${mitigations.length})`}
        defaultExpanded={false}
      >
        {mitigations.length > 0 ? (
          <ul style={{
            margin: 0,
            paddingLeft: 18,
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}>
            {mitigations.map((mit, idx) => (
              <li key={idx} style={{ fontSize: 12, color: '#2E7D32', fontWeight: 600 }}>
                {mit.name || mit.mitigation || `Mitigation ${idx + 1}`}
              </li>
            ))}
          </ul>
        ) : (
          <Box variant="p" color="text-body-secondary" fontSize="body-s">
            No mitigations for this node.
          </Box>
        )}
      </ExpandableSection>
    </SpaceBetween>
  );
}

export interface PropertiesPanelProps {
  selectedNode?: NodeData | null;
  attackTree?: ReportAttackTree | null;
  onFlowFieldChange?: (field: FlowField, value: string) => void;
  onNodeFieldChange: (field: NodeField, value: string) => void;
  isDirty?: boolean;
}

/**
 * PropertiesPanel — docked right-side panel emulating the Attack Flow Builder's
 * Properties pane. Context-sensitive: shows flow properties when no node is
 * selected, node properties when selected.
 */
export default function PropertiesPanel({
  selectedNode,
  onNodeFieldChange,
  isDirty,
}: PropertiesPanelProps) {
  const isNodeSelected = !!selectedNode;

  return (
    <div
      data-testid="properties-panel"
      style={{
        width: 340,
        minWidth: 340,
        height: '100%',
        background: '#fafafa',
        borderLeft: '1px solid #d5dbdb',
        overflowY: 'auto',
        padding: '12px 14px',
        fontFamily: '"Amazon Ember", "Helvetica Neue", Roboto, Arial, sans-serif',
      }}
    >
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 12,
        paddingBottom: 8,
        borderBottom: '1px solid #e9ebed',
      }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: '#16191f', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Properties
        </span>
        {isDirty && (
          <StatusIndicator type="info">Editing</StatusIndicator>
        )}
      </div>

      {/* Only show node properties when a node is selected */}
      {isNodeSelected ? (
        <NodeProperties
          nodeData={selectedNode}
          onNodeFieldChange={onNodeFieldChange}
        />
      ) : (
        <Box textAlign="center" padding="l" color="text-body-secondary">
          Click a node on the canvas to view and edit its properties.
        </Box>
      )}
    </div>
  );
}

export { FlowProperties };
