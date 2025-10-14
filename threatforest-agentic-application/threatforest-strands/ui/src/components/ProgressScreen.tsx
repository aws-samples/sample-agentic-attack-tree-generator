import React, { useEffect, useState } from 'react';
import { Box, Text } from 'ink';
import { StageIndicator, StageStatus } from './StageIndicator';
import { ProgressBar } from './ProgressBar';
import { ProgressDetails } from './ProgressDetails';
import { ParallelExecutionDisplay } from './ParallelExecutionDisplay';
import { ETADisplay } from './ETADisplay';
import { WorkflowState } from '../hooks/useWorkflow';

interface Props {
  state: WorkflowState;
}

interface Stage {
  name: string;
  status: StageStatus;
}

export const ProgressScreen: React.FC<Props> = ({ state }) => {
  const [stages, setStages] = useState<Stage[]>([
    { name: 'Context Analysis', status: 'pending' },
    { name: 'Information Extraction', status: 'pending' },
    { name: 'Attack Tree Generation', status: 'pending' },
    { name: 'Summary Generation', status: 'pending' }
  ]);

  useEffect(() => {
    const stageMap: Record<string, number> = {
      'setup': 0,
      'context': 0,
      'extraction': 1,
      'trees': 2,
      'summary': 3,
      'complete': 4
    };

    const currentIndex = stageMap[state.stage] ?? -1;

    setStages(prev => prev.map((stage, idx) => {
      if (idx < currentIndex) return { ...stage, status: 'complete' };
      if (idx === currentIndex) return { ...stage, status: 'running' };
      return { ...stage, status: 'pending' };
    }));
  }, [state.stage]);

  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="cyan">🔄 Processing Workflow</Text>
      <Box marginTop={1} />
      
      <StageIndicator stages={stages} />
      
      <ProgressDetails state={state} />
      
      {state.parallelTasks && state.parallelTasks.length > 0 && (
        <Box marginTop={1}>
          <ParallelExecutionDisplay 
            tasks={state.parallelTasks}
            title="Parallel Execution"
          />
        </Box>
      )}
    </Box>
  );
};
