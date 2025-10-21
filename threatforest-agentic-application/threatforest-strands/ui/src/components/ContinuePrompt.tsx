import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { useKeyboard } from '../hooks/useInput';

interface Props {
  message: string;
  onContinue: () => void;
  onSkip: () => void;
}

export const ContinuePrompt: React.FC<Props> = ({ message, onContinue, onSkip }) => {
  const [selected, setSelected] = useState<'continue' | 'skip'>('continue');

  useKeyboard({
    'up': () => setSelected('continue'),
    'down': () => setSelected('skip'),
    'y': () => onContinue(),
    'n': () => onSkip(),
    'enter': () => selected === 'continue' ? onContinue() : onSkip()
  });

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="green" padding={1}>
      <Text bold color="green">✅ {message}</Text>
      
      <Box marginTop={1} flexDirection="column">
        <Box>
          <Text color={selected === 'continue' ? 'cyan' : 'gray'}>
            {selected === 'continue' ? '▶ ' : '  '}Yes, continue (Y)
          </Text>
        </Box>
        <Box>
          <Text color={selected === 'skip' ? 'cyan' : 'gray'}>
            {selected === 'skip' ? '▶ ' : '  '}No, finish here (N)
          </Text>
        </Box>
      </Box>
      
      <Box marginTop={1}>
        <Text dimColor>Use arrow keys or Y/N to select, Enter to confirm</Text>
      </Box>
    </Box>
  );
};
