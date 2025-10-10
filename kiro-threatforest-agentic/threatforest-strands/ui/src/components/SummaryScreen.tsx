import React from 'react';
import { Box, Text } from 'ink';

interface Props {
  state: any;
}

export const SummaryScreen: React.FC<Props> = ({ state }) => {
  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="green">✓ Complete!</Text>
      <Box marginTop={1} />
      
      <Box flexDirection="column">
        <Text bold>Summary:</Text>
        <Text>• Threats Processed: 37</Text>
        <Text>• Attack Trees Generated: 12</Text>
        <Text>• TTC Mappings: 12</Text>
        <Text>• Cache Hit Rate: 45%</Text>
      </Box>
      
      <Box marginTop={1}>
        <Text dimColor>Output: ./threatforest_output</Text>
      </Box>
      
      <Box marginTop={1}>
        <Text color="cyan">Run 'threatforest cache stats' to view cache statistics</Text>
      </Box>
    </Box>
  );
};
