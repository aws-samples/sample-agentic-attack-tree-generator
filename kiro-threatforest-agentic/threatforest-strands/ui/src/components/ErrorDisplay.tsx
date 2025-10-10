import React from 'react';
import { Box, Text } from 'ink';

interface Props {
  error: string;
  onRetry?: () => void;
  onSkip?: () => void;
  onAbort?: () => void;
}

export const ErrorDisplay: React.FC<Props> = ({ error, onRetry, onSkip, onAbort }) => {
  return (
    <Box flexDirection="column" borderStyle="round" borderColor="red" padding={1}>
      <Text bold color="red">❌ Error</Text>
      <Box marginTop={1}>
        <Text>{error}</Text>
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>Options:</Text>
        {onRetry && <Text>• Press R to retry</Text>}
        {onSkip && <Text>• Press S to skip</Text>}
        {onAbort && <Text>• Press A to abort</Text>}
      </Box>
    </Box>
  );
};
