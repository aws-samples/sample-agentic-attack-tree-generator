import React from 'react';
import { Box, Text } from 'ink';
import { WorkflowState } from '../hooks/useWorkflow';

interface Props {
  state: WorkflowState;
}

export const SummaryScreen: React.FC<Props> = ({ state }) => {
  const data = state.data || {};
  
  return (
    <Box flexDirection="column" padding={1}>
      <Box borderStyle="double" borderColor="green" padding={1} flexDirection="column">
        <Text bold color="green">✓ Workflow Complete!</Text>
        
        <Box marginTop={1} flexDirection="column">
          <Text bold>📊 Summary:</Text>
          <Text>• Threats Processed: {data.threatsProcessed || 0}</Text>
          <Text>• Attack Trees Generated: {data.attackTrees || 0}</Text>
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
          <Text>• Review attack trees and summary report in output directory</Text>
          <Text>• Check logs in output/logs directory</Text>
          <Text>• Implement security controls based on identified threats</Text>
        </Box>
      </Box>
    </Box>
  );
};
