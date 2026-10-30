'use client';

import { useEffect, useRef, useState } from 'react';
import type { RunLogEntry } from '@threatforest/types';
import { getRunLogs } from '@/api/client';
import { RunLogPager } from '@/api/run-log-pager';
import { mergeRunLogs } from '@/utils/run-logs';

export function useRunLogs(runId: string, options: { live?: boolean; settleAfterCompletion?: boolean } = {}) {
  const [entries, setEntries] = useState<RunLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState('');
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const live = useRef(options.live ?? false);
  const settleUntil = useRef(0);
  const wasLive = useRef(options.live ?? false);
  const previousRun = useRef('');
  useEffect(() => {
    live.current = options.live ?? false;
    if (!wasLive.current && live.current) setRevision((value) => value + 1);
    if (wasLive.current && !live.current && options.settleAfterCompletion) settleUntil.current = Date.now() + 60_000;
    if (live.current) settleUntil.current = 0;
    wasLive.current = live.current;
  }, [options.live, options.settleAfterCompletion]);

  useEffect(() => {
    if (!runId) return;
    if (previousRun.current !== runId) {
      previousRun.current = runId;
      setEntries([]);
      setUpdatedAt(null);
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    const pager = new RunLogPager();
    let emptyPasses = 0;
    setLoading(true);
    setError('');
    const poll = async () => {
      let more = false;
      try {
        const page = await pager.next(
          (query) => getRunLogs(runId, query), controller.signal,
        );
        if (cancelled) return;
        more = page.more;
        setEntries((previous) => mergeRunLogs(previous, page.response.entries));
        setUpdatedAt(new Date().toISOString());
        setError('');
        emptyPasses = page.response.entries.length ? 0 : emptyPasses + 1;
      } catch (reason) {
        if (cancelled) return;
        setError(reason instanceof Error ? reason.message : 'Could not load execution logs.');
      } finally {
        if (!cancelled) {
          setLoading(false);
          setLoadingMore(more);
          if (more || live.current || Date.now() < settleUntil.current) {
            timer = setTimeout(() => void poll(), more ? 100 : Math.min(5000 * (1 + emptyPasses), 15_000));
          }
        }
      }
    };
    void poll();
    return () => {
      cancelled = true;
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [runId, revision]);

  return { entries, loading, loadingMore, error, updatedAt, refresh: () => setRevision((value) => value + 1) };
}
