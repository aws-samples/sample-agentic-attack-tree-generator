import React, { useState } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
import SelectInput from 'ink-select-input';
import { PythonBridge } from '../utils/pythonBridge';
import { useInput } from 'ink';
import * as path from 'path';

interface Props {
  onNext: (state: any) => void;
  state: any;
}

export const ConfigurationScreen: React.FC<Props> = ({ onNext, state }) => {
  const [step, setStep] = useState(0);
  const [projectPath, setProjectPath] = useState('');
  const [threatModelPath, setThreatModelPath] = useState('');
  const [awsProfile, setAwsProfile] = useState('default');
  const [model, setModel] = useState('');
  const [validating, setValidating] = useState(false);
  const [error, setError] = useState('');
  const [showAbort, setShowAbort] = useState(false);
  const [availableModels, setAvailableModels] = useState<Array<{label: string, value: string}>>([]);
  const [awsProfiles, setAwsProfiles] = useState<Array<{label: string, value: string}>>([]);
  const [loadingProfiles, setLoadingProfiles] = useState(false);

  const defaultModels = [
    { label: 'Claude Sonnet 4 (Cross-Region)', value: 'us.anthropic.claude-sonnet-4-20250514-v1:0' },
    { label: 'Claude 3.5 Sonnet v2', value: 'anthropic.claude-3-5-sonnet-20241022-v2:0' },
    { label: 'Claude 3.5 Haiku', value: 'anthropic.claude-3-5-haiku-20241022-v1:0' },
    { label: 'Claude 3 Opus', value: 'anthropic.claude-3-opus-20240229-v1:0' },
    { label: 'Claude 3 Haiku', value: 'anthropic.claude-3-haiku-20240307-v1:0' },
    { label: 'Titan Text Premier', value: 'amazon.titan-text-premier-v1:0' },
    { label: 'Titan Text Express', value: 'amazon.titan-text-express-v1' },
    { label: 'Llama 3.2 90B', value: 'meta.llama3-2-90b-instruct-v1:0' },
    { label: 'Llama 3.2 11B', value: 'meta.llama3-2-11b-instruct-v1:0' }
  ];

  const handleAwsProfileSelect = async (profile: string) => {
    setAwsProfile(profile);
    setValidating(true);
    setError('');
    
    const bridge = new PythonBridge();
    const result = await bridge.validateAwsCredentials(profile);
    
    setValidating(false);
    
    if (result.success) {
      if (result.data?.available_models) {
        const models = result.data.available_models.map((m: any) => ({
          label: m.modelName,
          value: m.modelId
        }));
        setAvailableModels(models);
      } else {
        setAvailableModels(defaultModels);
      }
      setStep(3);
    } else {
      setError(result.error || 'Failed to validate AWS credentials');
      setShowAbort(true);
    }
  };

  const handleSubmit = async () => {
    if (step === 0 && projectPath) {
      setStep(1);
    } else if (step === 1) {
      // Threat model path is optional, can be empty
      // Load AWS profiles before moving to step 2
      setLoadingProfiles(true);
      const bridge = new PythonBridge();
      const profilesResult = await bridge.getAwsProfiles();
      
      if (profilesResult.success && profilesResult.data) {
        const profiles = profilesResult.data as string[];
        setAwsProfiles(profiles.map(p => ({ label: p, value: p })));
      } else {
        setAwsProfiles([{ label: 'default', value: 'default' }]);
      }
      setLoadingProfiles(false);
      setStep(2);
    } else if (step === 3) {
      onNext({ projectPath, threatModelPath, awsProfile, bedrockModel: model, enableCache: true });
    }
  };

  const handleAbort = () => {
    process.exit(1);
  };

  // Handle back navigation with Escape key
  useInput((input, key) => {
    if (key.escape && step > 0 && !validating && !showAbort) {
      setStep(step - 1);
      setError('');
    }
  });

  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="cyan">⚙️  Configuration</Text>
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
      
      {step === 2 && !showAbort && (
        <Box flexDirection="column">
          <Text>✓ Project: {projectPath}</Text>
          {threatModelPath && <Text>✓ Threat Model: {threatModelPath}</Text>}
          <Box marginTop={1} />
          <Text>Select AWS Profile:</Text>
          {loadingProfiles ? (
            <Text color="yellow">Loading profiles...</Text>
          ) : (
            <SelectInput
              items={awsProfiles.length > 0 ? awsProfiles : [{ label: 'default', value: 'default' }]}
              onSelect={(item) => {
                const profile = typeof item === 'string' ? item : item.value;
                handleAwsProfileSelect(profile);
              }}
            />
          )}
          {validating && <Text color="yellow">Validating AWS credentials...</Text>}
          {error && <Text color="red">✗ {error}</Text>}
        </Box>
      )}
      
      {showAbort && (
        <Box flexDirection="column">
          <Text color="red">✗ {error}</Text>
          <Box marginTop={1}>
            <SelectInput
              items={[{ label: 'Exit and fix credentials', value: 'abort' }]}
              onSelect={handleAbort}
            />
          </Box>
        </Box>
      )}
      
      {step === 3 && (
        <Box flexDirection="column">
          <Text>✓ Project: {projectPath}</Text>
          {threatModelPath && <Text>✓ Threat Model: {threatModelPath}</Text>}
          <Text>✓ AWS Profile: {awsProfile}</Text>
          <Box marginTop={1} />
          <Text>Select Bedrock Model:</Text>
          <SelectInput
            items={availableModels.length > 0 ? availableModels : defaultModels}
            onSelect={(item) => {
              const modelId = typeof item === 'string' ? item : item.value;
              onNext({ projectPath, threatModelPath, awsProfile, bedrockModel: modelId, enableCache: true });
            }}
          />
        </Box>
      )}
    </Box>
  );
};
