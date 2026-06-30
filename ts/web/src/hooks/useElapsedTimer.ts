'use client';

import { useState, useEffect } from 'react';

/**
 * Format elapsed milliseconds as "Xm Ys" (e.g., "2m 15s").
 *
 * @param ms - Elapsed time in milliseconds
 * @returns Formatted duration string
 */
export function formatElapsed(ms: number | null | undefined): string {
  if (!ms || ms < 0) return '0m 0s';
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}m ${seconds}s`;
}

/**
 * Custom hook that tracks elapsed time between startTime and endTime.
 *
 * - When startTime is null, returns 0.
 * - When endTime is set, returns the fixed duration (endTime - startTime).
 * - When only startTime is set (in-progress), live-updates every second.
 *
 * @param startTime - Epoch ms when stage started
 * @param endTime - Epoch ms when stage completed
 * @returns Elapsed time in milliseconds
 */
export function useElapsedTimer(
  startTime: number | null | undefined,
  endTime: number | null | undefined,
): number {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!startTime) {
      setElapsed(0);
      return;
    }
    if (endTime) {
      setElapsed(endTime - startTime);
      return;
    }
    // Live-update every second while in-progress
    const tick = () => setElapsed(Date.now() - startTime);
    tick(); // immediate first tick
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [startTime, endTime]);

  return elapsed;
}
