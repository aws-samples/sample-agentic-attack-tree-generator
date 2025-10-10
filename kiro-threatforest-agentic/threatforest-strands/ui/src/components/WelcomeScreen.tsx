import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { PythonBridge } from '../utils/pythonBridge';

interface Props {
  onNext: (state: any) => void;
}

export const WelcomeScreen: React.FC<Props> = ({ onNext }) => {
  const [hasState, setHasState] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkState = async () => {
      const bridge = new PythonBridge();
      const result = await bridge.loadState();
      setHasState(result.success && result.data);
      setLoading(false);
      
      // Auto-advance after 2 seconds
      setTimeout(() => onNext({}), 2000);
    };
    
    checkState();
  }, []);

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
        ) : hasState ? (
          <Text color="yellow">⚠️  Found previous session. Use 'threatforest resume' to continue.</Text>
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
