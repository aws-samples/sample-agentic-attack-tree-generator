import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
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
  const [readyToStart, setReadyToStart] = useState(false);
  const [startInput, setStartInput] = useState('');

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
        setReadyToStart(true);
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
    setReadyToStart(true);
  };

  const handleStartSubmit = (value: string) => {
    if (value.toLowerCase() === 'start' || value.toLowerCase() === 's') {
      onNext({});
    }
  };

  if (showPrompt && savedState) {
    return <ResumePrompt state={savedState} onResume={handleResume} onRestart={handleRestart} />;
  }

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="green" padding={1}>
      <Text bold color="green">🌳 Welcome to ThreatForest!</Text>
      
      <Box marginTop={1}>
        <Text>
          ThreatForest is an AI-powered threat modeling tool that automatically generates{'\n'}
          attack trees and comprehensive security reports.
        </Text>
      </Box>
      
      <Box marginTop={1}>
        <Text bold>What ThreatForest does:</Text>
      </Box>
      
      <Box flexDirection="column" marginLeft={2}>
        <Text>• 📁 Analyzes ALL project content (docs, configs, images, threat models)</Text>
        <Text>• 👁️ Uses multimodal AI to analyze architecture diagrams and images</Text>
        <Text>• 🤖 Extracts project information using AWS Bedrock vision capabilities</Text>
        <Text>• 🎯 Generates standardized threat statements (T001, T002, T003...)</Text>
        <Text>• 🌳 Creates detailed attack trees for high-severity threats</Text>
        <Text>• 📄 Aligns attack steps to known intelligence sources such as the AWS TTC,</Text>
        <Text>     MITRE ATT&CK, or Wiz Cloud Security Framework</Text>
      </Box>
      
      <Box marginTop={1}>
        {loading ? (
          <Text dimColor>Checking for previous session...</Text>
        ) : readyToStart ? (
          <Box flexDirection="column">
            <Text color="cyan">Ready to start? Type 'start' or 's' to begin:</Text>
            <Box marginTop={1}>
              <Text color="green">&gt; </Text>
              <TextInput
                value={startInput}
                onChange={setStartInput}
                onSubmit={handleStartSubmit}
              />
            </Box>
          </Box>
        ) : null}
      </Box>
    </Box>
  );
};
