import React, { useState } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
import { useKeyboard } from '../hooks/useInput';

interface Config {
  projectPath: string;
  awsProfile: string;
  bedrockModel: string;
  enableCache: boolean;
}

interface Props {
  config: Config;
  onSave: (config: Config) => void;
  onCancel: () => void;
}

export const ConfigEditor: React.FC<Props> = ({ config, onSave, onCancel }) => {
  const [editing, setEditing] = useState<keyof Config | null>('projectPath');
  const [values, setValues] = useState(config);

  const fields: (keyof Config)[] = ['projectPath', 'awsProfile', 'bedrockModel'];
  const currentIndex = editing ? fields.indexOf(editing) : -1;

  useKeyboard({
    'escape': () => editing ? setEditing(null) : onCancel(),
    'tab': () => {
      if (!editing && currentIndex < fields.length - 1) {
        setEditing(fields[currentIndex + 1]);
      }
    }
  });

  const handleSubmit = (field: keyof Config, value: string) => {
    setValues(prev => ({ ...prev, [field]: value }));
    const nextIndex = currentIndex + 1;
    if (nextIndex < fields.length) {
      setEditing(fields[nextIndex]);
    } else {
      onSave(values);
    }
  };

  return (
    <Box flexDirection="column" padding={1}>
      <Text bold color="cyan">⚙️  Edit Configuration</Text>
      <Box marginTop={1} />
      
      <Box flexDirection="column">
        <Box>
          <Text>Project Path: </Text>
          {editing === 'projectPath' ? (
            <TextInput
              value={values.projectPath}
              onChange={v => setValues(prev => ({ ...prev, projectPath: v }))}
              onSubmit={v => handleSubmit('projectPath', v)}
            />
          ) : (
            <Text color="gray">{values.projectPath}</Text>
          )}
        </Box>
        
        <Box>
          <Text>AWS Profile: </Text>
          {editing === 'awsProfile' ? (
            <TextInput
              value={values.awsProfile}
              onChange={v => setValues(prev => ({ ...prev, awsProfile: v }))}
              onSubmit={v => handleSubmit('awsProfile', v)}
            />
          ) : (
            <Text color="gray">{values.awsProfile}</Text>
          )}
        </Box>
        
        <Box>
          <Text>Bedrock Model: </Text>
          {editing === 'bedrockModel' ? (
            <TextInput
              value={values.bedrockModel}
              onChange={v => setValues(prev => ({ ...prev, bedrockModel: v }))}
              onSubmit={v => handleSubmit('bedrockModel', v)}
            />
          ) : (
            <Text color="gray">{values.bedrockModel}</Text>
          )}
        </Box>
      </Box>
      
      <Box marginTop={1}>
        <Text dimColor>Tab: Next field | Enter: Confirm | Esc: Cancel</Text>
      </Box>
    </Box>
  );
};
