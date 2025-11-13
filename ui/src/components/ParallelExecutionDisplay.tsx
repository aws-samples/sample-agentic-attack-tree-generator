import React from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';

interface Task {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'complete' | 'error';
  progress?: number;
}

interface Props {
  tasks: Task[];
  title?: string;
}

export const ParallelExecutionDisplay: React.FC<Props> = ({ tasks, title }) => {
  const getIcon = (status: Task['status']) => {
    switch (status) {
      case 'pending': return '○';
      case 'running': return <Spinner type="dots" />;
      case 'complete': return '✓';
      case 'error': return '✗';
    }
  };

  const getColor = (status: Task['status']) => {
    switch (status) {
      case 'pending': return 'gray';
      case 'running': return 'yellow';
      case 'complete': return 'green';
      case 'error': return 'red';
    }
  };

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="cyan" padding={1}>
      {title && <Text bold color="cyan">{title}</Text>}
      <Box marginTop={1} flexDirection="column">
        {tasks.map(task => (
          <Box key={task.id}>
            <Text color={getColor(task.status)}>
              {getIcon(task.status)} {task.name}
              {task.progress !== undefined && ` (${task.progress}%)`}
            </Text>
          </Box>
        ))}
      </Box>
    </Box>
  );
};
