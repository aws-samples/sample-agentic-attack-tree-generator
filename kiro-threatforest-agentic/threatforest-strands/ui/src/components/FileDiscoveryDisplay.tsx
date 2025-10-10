import React from 'react';
import { Box, Text } from 'ink';

interface DiscoveryResult {
  threat_models: string[];
  source_code: string[];
  config_files: string[];
  documentation: string[];
  diagrams: string[];
  metadata: {
    total_files: number;
    total_size_bytes: number;
    discovery_time_ms: number;
    excluded_dirs: string[];
  };
}

interface Props {
  result: DiscoveryResult;
}

export const FileDiscoveryDisplay: React.FC<Props> = ({ result }) => {
  const { metadata } = result;
  const sizeMB = (metadata.total_size_bytes / 1024 / 1024).toFixed(2);
  const timeS = (metadata.discovery_time_ms / 1000).toFixed(2);

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="cyan" padding={1}>
      <Text bold color="cyan">📁 File Discovery Results</Text>
      
      <Box marginTop={1} flexDirection="column">
        <Text>Threat Models: {result.threat_models.length}</Text>
        <Text>Source Files: {result.source_code.length}</Text>
        <Text>Config Files: {result.config_files.length}</Text>
        <Text>Documentation: {result.documentation.length}</Text>
        <Text>Diagrams: {result.diagrams.length}</Text>
      </Box>
      
      <Box marginTop={1} flexDirection="column">
        <Text dimColor>Total Files: {metadata.total_files}</Text>
        <Text dimColor>Total Size: {sizeMB} MB</Text>
        <Text dimColor>Discovery Time: {timeS}s</Text>
      </Box>
    </Box>
  );
};
