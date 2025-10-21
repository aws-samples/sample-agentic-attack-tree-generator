import React from 'react';
import { Box, Text } from 'ink';
import { WorkflowState } from '../hooks/useWorkflow';

interface Props {
  state: WorkflowState;
}

export const SummaryScreen: React.FC<Props> = ({ state }) => {
  const data = state.data || {};
  
  const getNextSteps = () => {
    const mode = data.mode;
    
    if (mode === 'enrich') {
      return [
        '• Review enriched attack trees with TTC mappings in output directory',
        '• Check logs in output/logs directory',
        '• Add mitigations and detections using Option 3 (Mitigation and Detection Mapping)'
      ];
    }
    
    if (mode === 'mitigate' || mode === 'full') {
      return [
        '• Review mitigated attack trees in output directory',
        '• Check logs in output/logs directory',
        '• Implement mitigations and detections based on recommendations'
      ];
    }
    
    // Default for Option 1 only
    return [
      '• Review attack trees and summary report in output directory',
      '• Check logs in output/logs directory',
      '• Enrich attack trees with TTCs using Option 2 (TTC Enrichment)'
    ];
  };
  
  return (
    <Box flexDirection="column" padding={1}>
      <Box borderStyle="double" borderColor="green" padding={1} flexDirection="column">
        <Text bold color="green">✓ Workflow Complete!</Text>
        
        <Box marginTop={1} flexDirection="column">
          <Text bold>📊 Summary:</Text>
          <Text>• Threats Processed: {data.threatsProcessed || 0}</Text>
          <Text>• Attack Trees Generated: {data.attackTrees || 0}</Text>
          {data.totalMitigations !== undefined && (
            <Text>• Total Mitigations: {data.totalMitigations}</Text>
          )}
          {data.discovery && (
            <>
              <Text>• Threat Models Found: {data.discovery.threat_models?.length || 0}</Text>
              <Text>• Total Files Scanned: {data.discovery.metadata?.total_files || 0}</Text>
            </>
          )}
        </Box>
        
        <Box marginTop={1} flexDirection="column">
          <Text bold color="cyan">📁 Output Location:</Text>
          <Text>{data.outputDir || './output/attack_trees'}</Text>
        </Box>
        
        <Box marginTop={1} flexDirection="column">
          <Text bold>Next Steps:</Text>
          {getNextSteps().map((step, idx) => (
            <Text key={idx}>{step}</Text>
          ))}
        </Box>
      </Box>
    </Box>
  );
};
