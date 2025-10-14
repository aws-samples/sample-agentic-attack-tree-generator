import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { WorkflowState } from '../hooks/useWorkflow';

interface Props {
  state: WorkflowState;
}

export const ProgressDetails: React.FC<Props> = ({ state }) => {
  const [eta, setEta] = useState<string>('Calculating...');
  const [elapsed, setElapsed] = useState<string>('0s');

  useEffect(() => {
    if (!state.startTime) return;

    const interval = setInterval(() => {
      const now = Date.now();
      const elapsedMs = now - state.startTime;
      const elapsedSec = Math.floor(elapsedMs / 1000);
      
      // Format elapsed time
      const mins = Math.floor(elapsedSec / 60);
      const secs = elapsedSec % 60;
      setElapsed(mins > 0 ? `${mins}m ${secs}s` : `${secs}s`);
      
      // Calculate ETA
      if (state.progress.current > 0 && state.progress.current < state.progress.total) {
        const rate = state.progress.current / elapsedMs;
        const remaining = state.progress.total - state.progress.current;
        const etaMs = remaining / rate;
        const etaSec = Math.floor(etaMs / 1000);
        const etaMins = Math.floor(etaSec / 60);
        const etaSecs = etaSec % 60;
        setEta(etaMins > 0 ? `${etaMins}m ${etaSecs}s` : `${etaSecs}s`);
      } else if (state.progress.current >= state.progress.total) {
        setEta('Complete');
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [state.startTime, state.progress.current, state.progress.total]);

  const getStageDetails = () => {
    switch (state.stage) {
      case 'setup':
      case 'discovery':
        return {
          icon: '📁',
          text: state.message || 'Discovering project files...'
        };
      case 'extraction':
        return {
          icon: '🔍',
          text: state.message || 'Extracting threat information...'
        };
      case 'trees':
        return {
          icon: '🌳',
          text: state.message || 'Generating attack trees...'
        };
      case 'mapping':
        return {
          icon: '🗺️',
          text: state.message || 'Mapping to MITRE ATT&CK...'
        };
      case 'complete':
        return {
          icon: '✅',
          text: 'Analysis complete!'
        };
      default:
        return {
          icon: '⏳',
          text: 'Processing...'
        };
    }
  };

  const details = getStageDetails();
  const percentage = state.progress.total > 0 ? Math.round((state.progress.current / state.progress.total) * 100) : 0;
  const barWidth = 30;
  const filled = Math.round((percentage / 100) * barWidth);
  const empty = barWidth - filled;
  const bar = '█'.repeat(filled) + '░'.repeat(empty);

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="cyan" padding={1}>
      <Text bold color="cyan">📊 Progress Details</Text>
      <Box marginTop={1} flexDirection="column">
        <Text>
          {details.icon} {details.text}
        </Text>
        {state.progress.total > 0 && (
          <>
            <Text dimColor>
              Stage: {state.progress.current}/{state.progress.total}
            </Text>
            <Box marginTop={1} flexDirection="column">
              <Text>{percentage}% complete</Text>
              <Text color="cyan">{bar}</Text>
            </Box>
            {state.startTime && (
              <Box marginTop={1} flexDirection="column">
                <Text dimColor>Elapsed: {elapsed}</Text>
                <Text dimColor>ETA: {eta}</Text>
              </Box>
            )}
          </>
        )}
      </Box>
    </Box>
  );
};
