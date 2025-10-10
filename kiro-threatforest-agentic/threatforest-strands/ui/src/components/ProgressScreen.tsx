import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { StageIndicator, StageStatus } from './StageIndicator';
import { ProgressBar } from './ProgressBar';
import { CacheStats } from './CacheStats';

interface Props {
  onNext: (state: any) => void;
  state: any;
}

interface Stage {
  name: string;
  status: StageStatus;
}

export const ProgressScreen: React.FC<Props> = ({ onNext, state }) => {
  const [stages, setStages] = useState<Stage[]>([
    { name: 'File Discovery', status: 'running' },
    { name: 'Threat Extraction', status: 'pending' },
    { name: 'Attack Tree Generation', status: 'pending' },
    { name: 'TTC Mapping', status: 'pending' }
  ]);
  const [progress, setProgress] = useState({ current: 0, total: 100 });

  useEffect(() => {
    // Simulate workflow progression
    const stageNames = ['File Discovery', 'Threat Extraction', 'Attack Tree Generation', 'TTC Mapping'];
    let currentStageIndex = 0;

    const interval = setInterval(() => {
      setProgress(prev => {
        const newCurrent = prev.current + 10;
        if (newCurrent >= 100) {
          // Move to next stage
          setStages(prev => prev.map((stage, idx) => {
            if (idx === currentStageIndex) return { ...stage, status: 'complete' };
            if (idx === currentStageIndex + 1) return { ...stage, status: 'running' };
            return stage;
          }));
          
          currentStageIndex++;
          if (currentStageIndex >= stageNames.length) {
            clearInterval(interval);
            setTimeout(() => onNext({}), 1000);
          }
          return { current: 0, total: 100 };
        }
        return { current: newCurrent, total: 100 };
      });
    }, 300);

    return () => clearInterval(interval);
  }, []);

  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="cyan">🔄 Processing Workflow</Text>
      <Box marginTop={1} />
      
      <StageIndicator stages={stages} />
      
      <Box marginTop={1}>
        <ProgressBar 
          current={progress.current} 
          total={progress.total}
          label="Current Stage Progress"
        />
      </Box>
      
      <Box marginTop={1}>
        <Text dimColor>Project: {state.projectPath}</Text>
      </Box>
      
      <Box marginTop={1}>
        <CacheStats />
      </Box>
    </Box>
  );
};
