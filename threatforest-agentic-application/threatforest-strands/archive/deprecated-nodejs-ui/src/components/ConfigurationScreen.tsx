import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
import { PythonBridge } from '../utils/pythonBridge';
import { useInput } from 'ink';

interface Props {
  onNext: (state: any) => void;
  state: any;
}

export const ConfigurationScreen: React.FC<Props> = ({ onNext, state }) => {
  const [step, setStep] = useState(0);
  const [projectPath, setProjectPath] = useState('');
  const [threatModelPath, setThreatModelPath] = useState('');
  const [awsProfile, setAwsProfile] = useState('');
  const [model, setModel] = useState('');
  const [loadingConfig, setLoadingConfig] = useState(true);
  const [error, setError] = useState('');

  // Load config.yaml defaults on mount
  useEffect(() => {
    const loadConfig = async () => {
      const bridge = new PythonBridge();
      
      // Read config.yaml via Python
      try {
        const result = await bridge.executeCommand(
          'python',
          ['-c', `
import yaml
import sys
try:
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    print(config.get('aws', {}).get('default_profile', 'default'))
    print(config.get('models', {}).get('default_bedrock_model', ''))
except Exception as e:
    print('default')
    print('')
    sys.stderr.write(str(e))
`]
        );
        
        if (result.success && result.data) {
          const lines = result.data.trim().split('\n');
          const profile = lines[0] || 'default';
          const bedrock_model = lines[1] || '';
          
          setAwsProfile(profile);
          setModel(bedrock_model);
        }
      } catch (e) {
        // Use defaults if config read fails
        setAwsProfile('default');
        setModel('');
      }
      
      setLoadingConfig(false);
    };
    
    loadConfig();
  }, []);

  const handleSubmit = async () => {
    if (step === 0 && projectPath) {
      setStep(1);
    } else if (step === 1) {
      // Threat model path is optional - proceed directly to execution
      onNext({ 
        projectPath, 
        threatModelPath, 
        awsProfile, 
        bedrockModel: model, 
        enableCache: true 
      });
    }
  };

  // Handle back navigation with Escape key
  useInput((input: string, key: any) => {
    if (key.escape && step > 0) {
      setStep(step - 1);
      setError('');
    }
  });

  if (loadingConfig) {
    return (
      <Box flexDirection="column" padding={1}>
        <Text color="yellow">Loading configuration from config.yaml...</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="cyan">⚙️  Configuration</Text>
      <Text dimColor>Using AWS Profile: {awsProfile}</Text>
      <Text dimColor>Using Model: {model || 'Not configured'}</Text>
      {step > 0 && <Text dimColor>(Press ESC to go back)</Text>}
      <Box marginTop={1} />
      
      {step === 0 && (
        <Box flexDirection="column">
          <Text>Choose the directory that contains your project:</Text>
          <Text color="green" marginTop={1}>&gt; <TextInput
            value={projectPath}
            onChange={setProjectPath}
            onSubmit={handleSubmit}
            placeholder="Enter project path"
          /></Text>
        </Box>
      )}
      
      {step === 1 && (
        <Box flexDirection="column">
          <Text>✓ Project: {projectPath}</Text>
          <Box marginTop={1} />
          <Text>Threat Model Document (optional):</Text>
          <Text dimColor>Recommended: Use Threat Composer export file</Text>
          <Text dimColor>URL: https://awslabs.github.io/threat-composer/workspaces/default/dashboard</Text>
          <Text dimColor>Or provide any threat model document path (press Enter to skip)</Text>
          <Text color="green" marginTop={1}>&gt; <TextInput
            value={threatModelPath}
            onChange={setThreatModelPath}
            onSubmit={handleSubmit}
            placeholder="Path to threat model (optional)"
          /></Text>
        </Box>
      )}
      
      {error && (
        <Box marginTop={1}>
          <Text color="red">✗ {error}</Text>
        </Box>
      )}
    </Box>
  );
};
