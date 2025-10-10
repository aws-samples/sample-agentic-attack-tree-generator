import React from 'react';
import { Box, Text } from 'ink';
import { CacheStats } from './CacheStats';

interface Props {
  state: any;
}

export const SummaryScreen: React.FC<Props> = ({ state }) => {
  return (
    <Box flexDirection="column" padding={1}>
      <Box borderStyle="double" borderColor="green" padding={1}>
        <Text bold color="green">✓ Workflow Complete!</Text>
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Text bold>📊 Summary:</Text>
        <Text>• Threats Processed: 37</Text>
        <Text>• Attack Trees Generated: 12</Text>
        <Text>• TTC Mappings: 12</Text>
        <Text>• Total Duration: 5m 23s</Text>
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
