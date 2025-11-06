import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { useKeyboard } from '../hooks/useInput';

interface Props {
  error: string;
  onRetry?: () => void;
  onSkip?: () => void;
  onAbort?: () => void;
}

export const ErrorDisplay: React.FC<Props> = ({ error, onRetry, onSkip, onAbort }) => {
  const [selected, setSelected] = useState<'retry' | 'skip' | 'abort'>('retry');

  const options = [
    onRetry && 'retry',
    onSkip && 'skip',
    onAbort && 'abort'
  ].filter(Boolean) as ('retry' | 'skip' | 'abort')[];

  useKeyboard({
    'up': () => {
      const idx = options.indexOf(selected);
      setSelected(options[Math.max(0, idx - 1)]);
    },
    'down': () => {
      const idx = options.indexOf(selected);
      setSelected(options[Math.min(options.length - 1, idx + 1)]);
    },
    'r': () => onRetry?.(),
    's': () => onSkip?.(),
    'a': () => onAbort?.(),
    'enter': () => {
      if (selected === 'retry') onRetry?.();
      else if (selected === 'skip') onSkip?.();
      else if (selected === 'abort') onAbort?.();
    }
  });

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="red" padding={1}>
      <Text bold color="red">❌ Error</Text>
      <Box marginTop={1}>
        <Text>{error}</Text>
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>Options:</Text>
        {onRetry && (
          <Text color={selected === 'retry' ? 'cyan' : 'white'}>
            {selected === 'retry' ? '▶ ' : '  '}Retry (R)
          </Text>
        )}
        {onSkip && (
          <Text color={selected === 'skip' ? 'cyan' : 'white'}>
            {selected === 'skip' ? '▶ ' : '  '}Skip (S)
          </Text>
        )}
        {onAbort && (
          <Text color={selected === 'abort' ? 'cyan' : 'white'}>
            {selected === 'abort' ? '▶ ' : '  '}Abort (A)
          </Text>
        )}
      </Box>
      
      <Box marginTop={1}>
        <Text dimColor>Use arrow keys or letters to select, Enter to confirm</Text>
      </Box>
    </Box>
  );
};
