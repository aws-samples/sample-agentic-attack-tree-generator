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
  const [stages, setStages] = useState<Stage[]>([]);

  useEffect(() => {
    // Detect workflow type and set appropriate stages
    const isEnrichment = state.message?.includes('enrichment') || state.message?.includes('Enriching') || state.data?.mode === 'enrich';
    const isMitigation = state.message?.includes('mitigation') || state.message?.includes('mitigations') || state.data?.mode === 'mitigate';
    
    let newStages: Stage[];
    let stageMap: Record<string, number>;
    
    if (isEnrichment) {
      newStages = [
        { name: 'Loading TTC Matcher', status: 'pending' },
        { name: 'Enriching Attack Trees', status: 'pending' },
        { name: 'Finalizing Output', status: 'pending' }
      ];
      stageMap = {
        'trees': state.progress.current === 0 ? 0 : 1,
        'complete': 2
      };
    } else if (isMitigation) {
      newStages = [
        { name: 'Loading Mitigation Mapper', status: 'pending' },
        { name: 'Mapping Mitigations', status: 'pending' },
        { name: 'Finalizing Output', status: 'pending' }
      ];
      stageMap = {
        'summary': state.progress.current === 0 ? 0 : 1,
        'complete': 2
      };
    } else {
      // Full workflow
      newStages = [
        { name: 'Context Analysis', status: 'pending' },
        { name: 'Information Extraction', status: 'pending' },
        { name: 'Attack Tree Generation', status: 'pending' },
        { name: 'Summary Generation', status: 'pending' }
      ];
      stageMap = {
        'setup': 0,
        'context': 0,
        'extraction': 1,
        'trees': 2,
        'summary': 3,
        'complete': 4
      };
    }

    const currentIndex = stageMap[state.stage] ?? -1;
    const updatedStages = newStages.map((stage, idx) => {
      if (idx < currentIndex) return { ...stage, status: 'complete' as StageStatus };
      if (idx === currentIndex) return { ...stage, status: 'running' as StageStatus };
      return { ...stage, status: 'pending' as StageStatus };
    });

    setStages(updatedStages);
  }, [state.stage, state.message, state.progress.current, state.data?.mode]);

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
