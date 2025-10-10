import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { PythonBridge } from '../utils/pythonBridge';
import { ResumePrompt } from './ResumePrompt';

interface Props {
  onNext: (state: any) => void;
  onResume?: (state: any) => void;
}

export const WelcomeScreen: React.FC<Props> = ({ onNext, onResume }) => {
  const [hasState, setHasState] = useState(false);
  const [savedState, setSavedState] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showPrompt, setShowPrompt] = useState(false);

  useEffect(() => {
    const checkState = async () => {
      const bridge = new PythonBridge();
      const result = await bridge.loadState();
      
      if (result.success && result.data) {
        setHasState(true);
        setSavedState(result.data);
        setShowPrompt(true);
      } else {
        setLoading(false);
        setTimeout(() => onNext({}), 2000);
      }
    };
    
    checkState();
  }, []);

  const handleResume = () => {
    if (onResume && savedState) {
      onResume(savedState);
    }
  };

  const handleRestart = () => {
    setShowPrompt(false);
    setTimeout(() => onNext({}), 500);
  };

  if (showPrompt && savedState) {
    return <ResumePrompt state={savedState} onResume={handleResume} onRestart={handleRestart} />;
  }

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="cyan" padding={1}>
      <Text bold color="cyan">
        ╔══════════════════════════════════════════════════════════╗
      </Text>
      <Text bold color="cyan">
        ║              🛡️  THREATFOREST WIZARD                     ║
      </Text>
      <Text bold color="cyan">
        ║         AI-Driven Threat Modeling & Attack Trees        ║
      </Text>
      <Text bold color="cyan">
        ╚══════════════════════════════════════════════════════════╝
      </Text>
      
      <Box marginTop={1}>
        {loading ? (
          <Text>Checking for previous session...</Text>
        ) : (
          <Text color="green">✓ Ready to start new session</Text>
        )}
      </Box>
      
      <Box marginTop={1}>
        <Text dimColor>Starting configuration...</Text>
      </Box>
    </Box>
  );
};
