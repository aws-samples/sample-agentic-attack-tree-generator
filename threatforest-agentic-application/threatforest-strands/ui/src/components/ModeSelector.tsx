import React, { useState } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';

interface Props {
  onSelect: (mode: 'full' | 'enrich' | 'mitigate') => void;
}

export const ModeSelector: React.FC<Props> = ({ onSelect }) => {
  const [input, setInput] = useState('');

  const handleSubmit = (value: string) => {
    const choice = value.toLowerCase();
    if (choice === '1' || choice === 'full') {
      onSelect('full');
    } else if (choice === '2' || choice === 'enrich') {
      onSelect('enrich');
    } else if (choice === '3' || choice === 'mitigate') {
      onSelect('mitigate');
    }
  };

  return (
    <Box flexDirection="column" marginTop={1}>
      <Text bold color="cyan">Select Mode:</Text>
      <Box flexDirection="column" marginLeft={2} marginTop={1}>
        <Text>1. 🌳 Full Analysis - Generate attack trees from project</Text>
        <Text>2. 🎯 Enrich - Add TTC technique mappings to existing attack trees</Text>
        <Text>3. 🛡️ Mitigate - Add mitigation recommendations to enriched trees</Text>
      </Box>
      <Box marginTop={1}>
        <Text color="green">&gt; </Text>
        <TextInput
          value={input}
          onChange={setInput}
          onSubmit={handleSubmit}
          placeholder="Enter 1, 2, or 3"
        />
      </Box>
    </Box>
  );
};
