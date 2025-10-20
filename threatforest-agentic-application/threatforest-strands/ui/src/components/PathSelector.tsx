import React, { useState } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';

interface Props {
  mode: 'enrich' | 'mitigate';
  onSubmit: (inputDir: string, outputDir: string) => void;
}

export const PathSelector: React.FC<Props> = ({ mode, onSubmit }) => {
  const [inputDir, setInputDir] = useState('');
  const [outputDir, setOutputDir] = useState('');
  const [step, setStep] = useState<'input' | 'output'>('input');

  const handleInputSubmit = (value: string) => {
    setInputDir(value);
    setStep('output');
  };

  const handleOutputSubmit = (value: string) => {
    setOutputDir(value);
    onSubmit(inputDir, value);
  };

  const defaultInput = mode === 'enrich' 
    ? './output/attack_trees' 
    : './output/enriched';
  
  const defaultOutput = mode === 'enrich'
    ? './output/enriched'
    : './output/mitigated';

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="cyan" padding={1}>
      <Text bold color="cyan">
        {mode === 'enrich' ? '🎯 TTC Enrichment' : '🛡️ Mitigation Mapping'}
      </Text>
      
      {step === 'input' ? (
        <Box flexDirection="column" marginTop={1}>
          <Text>Enter input directory (or press Enter for default):</Text>
          <Text dimColor>Default: {defaultInput}</Text>
          <Text color="green" marginTop={1}>&gt; <TextInput
            value={inputDir}
            onChange={setInputDir}
            onSubmit={handleInputSubmit}
            placeholder={defaultInput}
          /></Text>
        </Box>
      ) : (
        <Box flexDirection="column" marginTop={1}>
          <Text>Input: {inputDir || defaultInput}</Text>
          <Text marginTop={1}>Enter output directory (or press Enter for default):</Text>
          <Text dimColor>Default: {defaultOutput}</Text>
          <Text color="green" marginTop={1}>&gt; <TextInput
            value={outputDir}
            onChange={setOutputDir}
            onSubmit={handleOutputSubmit}
            placeholder={defaultOutput}
          /></Text>
        </Box>
      )}
    </Box>
  );
};
