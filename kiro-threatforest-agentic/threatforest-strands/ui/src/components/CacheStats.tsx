import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { PythonBridge } from '../utils/pythonBridge';

export const CacheStats: React.FC = () => {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      const bridge = new PythonBridge();
      const result = await bridge.getCacheStats();
      if (result.success) {
        setStats(result.data);
      }
      setLoading(false);
    };
    
    fetchStats();
  }, []);

  if (loading) return <Text dimColor>Loading cache stats...</Text>;
  if (!stats) return null;

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
      <Text bold>📊 Cache Statistics</Text>
      <Box marginTop={1} flexDirection="column">
        <Text>Hits: {stats.hits}</Text>
        <Text>Misses: {stats.misses}</Text>
        <Text>Hit Rate: {stats.hit_rate}</Text>
        <Text>Size: {stats.cache_size_mb} MB</Text>
        <Text>Entries: {stats.entry_count}</Text>
      </Box>
    </Box>
  );
};
