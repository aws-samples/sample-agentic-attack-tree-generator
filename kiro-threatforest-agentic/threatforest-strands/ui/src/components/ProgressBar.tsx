import React from 'react';
import { Box, Text } from 'ink';

interface Props {
  current: number;
  total: number;
  label?: string;
  showPercentage?: boolean;
}

export const ProgressBar: React.FC<Props> = ({ 
  current, 
  total, 
  label, 
  showPercentage = true 
}) => {
  const percentage = total > 0 ? Math.round((current / total) * 100) : 0;
  const barWidth = 30;
  const filled = Math.round((percentage / 100) * barWidth);
  const empty = barWidth - filled;
  
  const bar = '█'.repeat(filled) + '░'.repeat(empty);
  
  return (
    <Box flexDirection="column">
      {label && <Text>{label}</Text>}
      <Box>
        <Text color="cyan">{bar}</Text>
        {showPercentage && (
          <Text> {percentage}% ({current}/{total})</Text>
        )}
      </Box>
    </Box>
  );
};
