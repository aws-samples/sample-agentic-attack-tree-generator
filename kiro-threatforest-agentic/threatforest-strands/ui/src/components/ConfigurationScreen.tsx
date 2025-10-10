import React, { useState } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
import SelectInput from 'ink-select-input';

interface Props {
  onNext: (state: any) => void;
  state: any;
}

export const ConfigurationScreen: React.FC<Props> = ({ onNext, state }) => {
  const [step, setStep] = useState(0);
  const [projectPath, setProjectPath] = useState('');
  const [awsProfile, setAwsProfile] = useState('default');
  const [model, setModel] = useState('');

  const models = [
    { label: 'Claude Sonnet 4', value: 'us.anthropic.claude-sonnet-4-20250514-v1:0' },
    { label: 'Claude Opus 4.1', value: 'us.anthropic.claude-opus-4-1-20250805-v1:0' },
    { label: 'Claude 3.5 Sonnet', value: 'anthropic.claude-3-5-sonnet-20241022-v2:0' },
    { label: 'Claude 3.5 Haiku', value: 'anthropic.claude-3-5-haiku-20241022-v1:0' },
    { label: 'Claude 3 Opus', value: 'anthropic.claude-3-opus-20240229-v1:0' },
    { label: 'Claude 3 Haiku', value: 'anthropic.claude-3-haiku-20240307-v1:0' },
    { label: 'Titan Text Premier', value: 'amazon.titan-text-premier-v1:0' },
    { label: 'Titan Text Express', value: 'amazon.titan-text-express-v1' },
    { label: 'Llama 3.2 90B', value: 'meta.llama3-2-90b-instruct-v1:0' },
    { label: 'Llama 3.2 11B', value: 'meta.llama3-2-11b-instruct-v1:0' }
  ];

  const handleSubmit = () => {
    if (step === 0 && projectPath) {
      setStep(1);
    } else if (step === 1 && awsProfile) {
      setStep(2);
    } else if (step === 2) {
      onNext({ projectPath, awsProfile, bedrockModel: model, enableCache: true });
    }
  };

  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="cyan">⚙️  Configuration</Text>
      <Box marginTop={1} />
      
      {step === 0 && (
        <Box flexDirection="column">
          <Text>Project Path:</Text>
          <TextInput
            value={projectPath}
            onChange={setProjectPath}
            onSubmit={handleSubmit}
            placeholder="/path/to/project"
          />
        </Box>
      )}
      
      {step === 1 && (
        <Box flexDirection="column">
          <Text>✓ Project: {projectPath}</Text>
          <Box marginTop={1} />
          <Text>AWS Profile:</Text>
          <TextInput
            value={awsProfile}
            onChange={setAwsProfile}
            onSubmit={handleSubmit}
            placeholder="default"
          />
        </Box>
      )}
      
      {step === 2 && (
        <Box flexDirection="column">
          <Text>✓ Project: {projectPath}</Text>
          <Text>✓ AWS Profile: {awsProfile}</Text>
          <Box marginTop={1} />
          <Text>Select Bedrock Model:</Text>
          <SelectInput
            items={models}
            onSelect={(item) => {
              setModel(item.value);
              setTimeout(() => handleSubmit(), 100);
            }}
          />
        </Box>
      )}
    </Box>
  );
};
