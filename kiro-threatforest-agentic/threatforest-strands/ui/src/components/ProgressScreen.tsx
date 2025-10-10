import React, { useEffect, useState } from 'react';
import { Box, Text } from 'ink';
import { StageIndicator, StageStatus } from './StageIndicator';
import { ProgressBar } from './ProgressBar';
import { CacheStats } from './CacheStats';
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
    { name: 'File Discovery', status: 'pending' },
    { name: 'Threat Extraction', status: 'pending' },
    { name: 'Attack Tree Generation', status: 'pending' },
    { name: 'TTC Mapping', status: 'pending' }
  ]);

  useEffect(() => {
    const stageMap: Record<string, number> = {
      'discovery': 0,
      'extraction': 1,
      'trees': 2,
      'mapping': 3,
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
      
      {state.message && (
        <Box marginTop={1}>
          <Text dimColor>{state.message}</Text>
        </Box>
      )}
      
      <Box marginTop={1}>
        <ProgressBar 
          current={state.progress.current} 
          total={state.progress.total}
          label="Overall Progress"
        />
      </Box>
      
      {state.startTime && (
        <Box marginTop={1}>
          <ETADisplay 
            startTime={state.startTime}
            current={state.progress.current}
            total={state.progress.total}
          />
        </Box>
      )}
      
      {state.parallelTasks && state.parallelTasks.length > 0 && (
        <Box marginTop={1}>
          <ParallelExecutionDisplay 
            tasks={state.parallelTasks}
            title="Parallel Execution"
          />
        </Box>
      )}
      
      <Box marginTop={1}>
        <CacheStats />
      </Box>
    </Box>
  );
};
