import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { useKeyboard } from '../hooks/useInput';

interface Threat {
  id: string;
  severity: string;
  statement: string;
}

interface Props {
  threats: Threat[];
  onSelect: (selected: Threat[]) => void;
  onCancel: () => void;
}

export const ThreatSelector: React.FC<Props> = ({ threats, onSelect, onCancel }) => {
  const [cursor, setCursor] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());

  useKeyboard({
    'up': () => setCursor(prev => Math.max(0, prev - 1)),
    'down': () => setCursor(prev => Math.min(threats.length - 1, prev + 1)),
    'space': () => {
      setSelected(prev => {
        const next = new Set(prev);
        if (next.has(cursor)) next.delete(cursor);
        else next.add(cursor);
        return next;
      });
    },
    'a': () => setSelected(new Set(threats.map((_, i) => i))),
    'c': () => setSelected(new Set()),
    'enter': () => {
      const selectedThreats = Array.from(selected).map(i => threats[i]);
      onSelect(selectedThreats);
    },
    'escape': () => onCancel()
  });

  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="cyan">Select Threats to Process</Text>
      <Box marginTop={1} />
      
      <Box flexDirection="column">
        {threats.slice(0, 10).map((threat, idx) => (
          <Box key={idx}>
            <Text color={cursor === idx ? 'cyan' : 'white'}>
              {cursor === idx ? '▶ ' : '  '}
              [{selected.has(idx) ? '✓' : ' '}] {threat.id} - {threat.severity}
            </Text>
          </Box>
        ))}
        {threats.length > 10 && (
          <Text dimColor>... and {threats.length - 10} more</Text>
        )}
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>Space: Toggle | A: All | C: Clear | Enter: Confirm | Esc: Cancel</Text>
        <Text dimColor>Selected: {selected.size}/{threats.length}</Text>
      </Box>
    </Box>
  );
};
