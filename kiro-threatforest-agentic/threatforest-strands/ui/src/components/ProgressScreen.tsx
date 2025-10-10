import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';

interface Props {
  onNext: (state: any) => void;
  state: any;
}

type Stage = 'discovery' | 'extraction' | 'trees' | 'mapping' | 'done';

export const ProgressScreen: React.FC<Props> = ({ onNext, state }) => {
  const [stage, setStage] = useState<Stage>('discovery');
  const [progress, setProgress] = useState({ current: 0, total: 0 });

  useEffect(() => {
    // Simulate workflow progression
    const stages: Stage[] = ['discovery', 'extraction', 'trees', 'mapping', 'done'];
    let currentIndex = 0;

    const interval = setInterval(() => {
      currentIndex++;
      if (currentIndex < stages.length) {
        setStage(stages[currentIndex]);
      } else {
        clearInterval(interval);
        setTimeout(() => onNext({}), 1000);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  const getStageIcon = (s: Stage) => {
    if (s === stage) return <Spinner type="dots" />;
    const index = ['discovery', 'extraction', 'trees', 'mapping', 'done'].indexOf(s);
    const currentIndex = ['discovery', 'extraction', 'trees', 'mapping', 'done'].indexOf(stage);
    return index < currentIndex ? '✓' : '○';
  };

  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="cyan">🔄 Processing</Text>
      <Box marginTop={1} />
      
      <Box flexDirection="column">
        <Box>
          <Text>{getStageIcon('discovery')} </Text>
          <Text color={stage === 'discovery' ? 'yellow' : 'gray'}>
            File Discovery
          </Text>
        </Box>
        
        <Box>
          <Text>{getStageIcon('extraction')} </Text>
          <Text color={stage === 'extraction' ? 'yellow' : 'gray'}>
            Threat Extraction
          </Text>
        </Box>
        
        <Box>
          <Text>{getStageIcon('trees')} </Text>
          <Text color={stage === 'trees' ? 'yellow' : 'gray'}>
            Attack Tree Generation
          </Text>
        </Box>
        
        <Box>
          <Text>{getStageIcon('mapping')} </Text>
          <Text color={stage === 'mapping' ? 'yellow' : 'gray'}>
            TTC Mapping
          </Text>
        </Box>
      </Box>
      
      <Box marginTop={1}>
        <Text dimColor>Project: {state.projectPath}</Text>
      </Box>
    </Box>
  );
};
