import React from 'react';
import { Box, Text } from 'ink';
import { CacheStats } from './CacheStats';
import { WorkflowState } from '../hooks/useWorkflow';

interface Props {
  state: WorkflowState;
}

export const SummaryScreen: React.FC<Props> = ({ state }) => {
  const data = state.data || {};
  
  return (
    <Box flexDirection="column" padding={1}>
      <Box borderStyle="double" borderColor="green" padding={1}>
        <Text bold color="green">✓ Workflow Complete!</Text>
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Text bold>📊 Summary:</Text>
        <Text>• Threats Processed: {data.threatsProcessed || 0}</Text>
        <Text>• Attack Trees Generated: {data.attackTrees || 0}</Text>
        <Text>• TTC Mappings: {data.ttcMappings || 0}</Text>
        {data.discovery && (
          <>
            <Text>• Threat Models Found: {data.discovery.threat_models?.length || 0}</Text>
            <Text>• Total Files Scanned: {data.discovery.metadata?.total_files || 0}</Text>
          </>
        )}
      </Box>
      
      <Box marginTop={1}>
        <CacheStats />
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Text bold color="cyan">📁 Output Location:</Text>
        <Text>./threatforest_output</Text>
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>Next Steps:</Text>
        <Text dimColor>• Review attack trees in output directory</Text>
        <Text dimColor>• Run 'threatforest cache stats' for cache details</Text>
        <Text dimColor>• Use 'threatforest resume' to continue from checkpoint</Text>
      </Box>
    </Box>
  );
};
