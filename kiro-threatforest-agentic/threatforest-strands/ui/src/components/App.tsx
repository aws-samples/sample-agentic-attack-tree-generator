import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { WelcomeScreen } from './WelcomeScreen';
import { ConfigurationScreen } from './ConfigurationScreen';
import { ProgressScreen } from './ProgressScreen';
import { SummaryScreen } from './SummaryScreen';

export type Screen = 'welcome' | 'config' | 'progress' | 'summary';

export interface AppState {
  projectPath?: string;
  awsProfile?: string;
  bedrockModel?: string;
  enableCache?: boolean;
}

export const App: React.FC = () => {
  const [screen, setScreen] = useState<Screen>('welcome');
  const [state, setState] = useState<AppState>({});

  const handleNext = (newState: Partial<AppState>) => {
    setState({ ...state, ...newState });
    
    if (screen === 'welcome') setScreen('config');
    else if (screen === 'config') setScreen('progress');
    else if (screen === 'progress') setScreen('summary');
  };

  return (
    <Box flexDirection="column" padding={1}>
      {screen === 'welcome' && <WelcomeScreen onNext={handleNext} />}
      {screen === 'config' && <ConfigurationScreen onNext={handleNext} state={state} />}
      {screen === 'progress' && <ProgressScreen onNext={handleNext} state={state} />}
      {screen === 'summary' && <SummaryScreen state={state} />}
    </Box>
  );
};
