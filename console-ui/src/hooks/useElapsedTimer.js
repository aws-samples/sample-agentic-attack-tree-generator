import { useState, useEffect } from 'react';

/**
 * Format elapsed milliseconds as "Xm Ys" (e.g., "2m 15s").
 * @param {number} ms - Elapsed time in milliseconds
 * @returns {string} Formatted duration string
 */
export function formatElapsed(ms) {
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
 * @param {number|null} startTime - Epoch ms when stage started
 * @param {number|null} endTime - Epoch ms when stage completed
 * @returns {number} Elapsed time in milliseconds
 */
export function useElapsedTimer(startTime, endTime) {
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
