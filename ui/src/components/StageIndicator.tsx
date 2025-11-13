import React from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';

export type StageStatus = 'pending' | 'running' | 'complete' | 'error';

interface Stage {
  name: string;
  status: StageStatus;
}

interface Props {
  stages: Stage[];
}

export const StageIndicator: React.FC<Props> = ({ stages }) => {
  const getIcon = (status: StageStatus) => {
    switch (status) {
      case 'pending': return '○';
      case 'running': return <Spinner type="dots" />;
      case 'complete': return '✓';
      case 'error': return '✗';
    }
  };

  const getColor = (status: StageStatus) => {
    switch (status) {
      case 'pending': return 'gray';
      case 'running': return 'yellow';
      case 'complete': return 'green';
      case 'error': return 'red';
    }
  };

  return (
    <Box flexDirection="column">
      {stages.map((stage, index) => (
        <Box key={index}>
          <Text color={getColor(stage.status)}>
            {getIcon(stage.status)} {stage.name}
          </Text>
        </Box>
      ))}
    </Box>
  );
};
