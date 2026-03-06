import React, { useState, useEffect, useCallback } from 'react';
import SpaceBetween from '@cloudscape-design/components/space-between';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Textarea from '@cloudscape-design/components/textarea';
import Select from '@cloudscape-design/components/select';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Link from '@cloudscape-design/components/link';
import StatusIndicator from '@cloudscape-design/components/status-indicator';

function buildMitreUrl(techniqueId) {
  if (!techniqueId) return null;
  const parts = techniqueId.split('.');
  if (parts[1]) return `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`;
  return `https://attack.mitre.org/techniques/${parts[0]}/`;
}

/**
 * Flow-level properties shown when no node is selected.
 */
function FlowProperties({ attackTree, onFieldChange }) {
  if (!attackTree) return null;
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
          selectedOption={
            attackTree.priority
              ? { label: attackTree.priority, value: attackTree.priority }
              : null
          }
          onChange={({ detail }) => onFieldChange('priority', detail.selectedOption.value)}
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

/**
 * Node-level properties shown when a node is selected.
 */
function NodeProperties({ nodeData, onNodeFieldChange }) {
  if (!nodeData) return null;

  const { label, nodeId, category, description, ttcMappings = [], mitigations = [] } = nodeData;

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
          <Badge color={
            category === 'attack' ? 'red' :
            category === 'goal' ? 'red' :
            category === 'fact' ? 'blue' :
            category === 'mitigation' ? 'green' : 'grey'
          }>
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

      {/* MITRE ATT&CK Mappings */}
      {ttcMappings.length > 0 && (
        <ExpandableSection
          headerText={`MITRE ATT&CK Mappings (${ttcMappings.length})`}
          defaultExpanded
        >
          <SpaceBetween size="s">
            {ttcMappings.map((mapping, idx) => {
              const url = buildMitreUrl(mapping.technique_id);
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
                  {mapping.tactics?.length > 0 && (
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

      {/* Mitigations */}
      <ExpandableSection
        headerText={`🛡️ Mitigations (${mitigations.length})`}
        defaultExpanded={false}
      >
        {mitigations.length > 0 ? (
          <SpaceBetween size="xs">
            {mitigations.map((mit, idx) => (
              <div key={idx} style={{
                padding: '6px 10px',
                background: '#f0fdf4',
                borderRadius: 6,
                border: '1px solid #C8E6C9',
              }}>
                <div style={{ fontWeight: 600, fontSize: 12, color: '#2E7D32' }}>
                  {mit.name || mit.mitigation || `Mitigation ${idx + 1}`}
                </div>
                {(mit.description || mit.details) && (
                  <div style={{ fontSize: 11, color: '#555', marginTop: 2 }}>
                    {mit.description || mit.details}
                  </div>
                )}
              </div>
            ))}
          </SpaceBetween>
        ) : (
          <Box variant="p" color="text-body-secondary" fontSize="body-s">
            No mitigations for this node.
          </Box>
        )}
      </ExpandableSection>
    </SpaceBetween>
  );
}

/**
 * PropertiesPanel — docked right-side panel emulating the Attack Flow Builder's Properties pane.
 * Context-sensitive: shows flow properties when no node is selected, node properties when selected.
 */
export default function PropertiesPanel({
  selectedNode,
  attackTree,
  onFlowFieldChange,
  onNodeFieldChange,
  isDirty,
}) {
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