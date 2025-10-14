import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { WelcomeScreen } from './WelcomeScreen';
import { ConfigurationScreen } from './ConfigurationScreen';
import { ProgressScreen } from './ProgressScreen';
import { SummaryScreen } from './SummaryScreen';
import { ErrorDisplay } from './ErrorDisplay';
import { useWorkflow } from '../hooks/useWorkflow';

export type Screen = 'welcome' | 'config' | 'progress' | 'summary' | 'error';

export interface AppState {
  projectPath?: string;
  awsProfile?: string;
  bedrockModel?: string;
  enableCache?: boolean;
}

export const App: React.FC = () => {
  const [screen, setScreen] = useState<Screen>('welcome');
  const [appState, setAppState] = useState<AppState>({});
  const { state: workflowState, executeWorkflow, clearError } = useWorkflow();

  const handleNext = async (newState: Partial<AppState>) => {
    setAppState({ ...appState, ...newState });
    
    if (screen === 'welcome') {
      setScreen('config');
    } else if (screen === 'config') {
      setScreen('progress');
      
      // Execute workflow
      const config = {
        projectPath: newState.projectPath || appState.projectPath || '',
        awsProfile: newState.awsProfile || appState.awsProfile,
        bedrockModel: newState.bedrockModel || appState.bedrockModel || '',
        enableCache: newState.enableCache ?? appState.enableCache ?? true
      };
      
      const result = await executeWorkflow(config);
      
      if (result.success) {
        setScreen('summary');
      } else {
        setScreen('error');
      }
    }
  };

  const handleRetry = () => {
    clearError();
    setScreen('config');
  };

  return (
    <Box flexDirection="column" padding={1}>
      {screen === 'welcome' && <WelcomeScreen onNext={handleNext} />}
      {screen === 'config' && <ConfigurationScreen onNext={handleNext} state={appState} />}
      {screen === 'progress' && <ProgressScreen state={workflowState} />}
      {screen === 'summary' && <SummaryScreen state={workflowState} />}
      {screen === 'error' && workflowState.error && (
        <ErrorDisplay 
          error={workflowState.error} 
          onRetry={handleRetry}
          onAbort={() => process.exit(1)}
        />
      )}
    </Box>
  );
};
