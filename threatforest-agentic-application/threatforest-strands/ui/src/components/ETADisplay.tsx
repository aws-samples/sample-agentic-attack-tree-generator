import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';

interface Props {
  startTime: number;
  current: number;
  total: number;
}

export const ETADisplay: React.FC<Props> = ({ startTime, current, total }) => {
  const [eta, setEta] = useState<string>('Calculating...');
  const [elapsed, setElapsed] = useState<string>('0s');

  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      const elapsedMs = now - startTime;
      const elapsedSec = Math.floor(elapsedMs / 1000);
      
      // Format elapsed time
      const mins = Math.floor(elapsedSec / 60);
      const secs = elapsedSec % 60;
      setElapsed(mins > 0 ? `${mins}m ${secs}s` : `${secs}s`);
      
      // Calculate ETA
      if (current > 0 && current < total) {
        const rate = current / elapsedMs;
        const remaining = total - current;
        const etaMs = remaining / rate;
        const etaSec = Math.floor(etaMs / 1000);
        const etaMins = Math.floor(etaSec / 60);
        const etaSecs = etaSec % 60;
        setEta(etaMins > 0 ? `${etaMins}m ${etaSecs}s` : `${etaSecs}s`);
      } else if (current >= total) {
        setEta('Complete');
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [startTime, current, total]);

  return (
    <Box flexDirection="column">
      <Text>Elapsed: {elapsed}</Text>
      <Text>ETA: {eta}</Text>
    </Box>
  );
};
