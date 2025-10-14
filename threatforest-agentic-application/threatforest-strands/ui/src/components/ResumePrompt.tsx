import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { useKeyboard } from '../hooks/useInput';

interface Props {
  state: any;
  onResume: () => void;
  onRestart: () => void;
}

export const ResumePrompt: React.FC<Props> = ({ state, onResume, onRestart }) => {
  const [selected, setSelected] = useState<'resume' | 'restart'>('resume');

  useKeyboard({
    'up': () => setSelected('resume'),
    'down': () => setSelected('restart'),
    'r': () => onResume(),
    'n': () => onRestart(),
    'enter': () => selected === 'resume' ? onResume() : onRestart()
  });

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="yellow" padding={1}>
      <Text bold color="yellow">⚠️  Previous Session Found</Text>
      
      <Box marginTop={1} flexDirection="column">
        <Text>Stage: {state.current_stage}</Text>
        <Text>Started: {new Date(state.started_at).toLocaleString()}</Text>
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Box>
          <Text color={selected === 'resume' ? 'cyan' : 'gray'}>
            {selected === 'resume' ? '▶ ' : '  '}Resume from checkpoint (R)
          </Text>
        </Box>
        <Box>
          <Text color={selected === 'restart' ? 'cyan' : 'gray'}>
            {selected === 'restart' ? '▶ ' : '  '}Start new session (N)
          </Text>
        </Box>
      </Box>
      
      <Box marginTop={1}>
        <Text dimColor>Use arrow keys or R/N to select, Enter to confirm</Text>
      </Box>
    </Box>
  );
};
