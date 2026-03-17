import React, { useState } from 'react';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Input from '@cloudscape-design/components/input';
import { pickDirectory } from '../api-client';

export default function DirectoryPicker({ value, onChange, placeholder }) {
  const [picking, setPicking] = useState(false);

  const handleBrowse = async () => {
    setPicking(true);
    try {
      const result = await pickDirectory();
      if (result.path) {
        onChange(result.path);
      }
    } catch {
      // User cancelled or dialog failed — silently ignore
    } finally {
      setPicking(false);
    }
  };

  return (
    <SpaceBetween direction="horizontal" size="xs">
      <div style={{ flexGrow: 1 }}>
        <Input
          value={value}
          onChange={({ detail }) => onChange(detail.value)}
          placeholder={placeholder || '/path/to/project'}
        />
      </div>
      <Button
        iconName="folder-open"
        variant="normal"
        onClick={handleBrowse}
        loading={picking}
      >
        Browse
      </Button>
    </SpaceBetween>
  );
}
