import { expect, it } from 'vitest';
import type { RunId, RunLogsResponse } from '@threatforest/types';
import { RunLogPager, type LogPageQuery } from './run-log-pager';

const end = '2026-09-16T12:00:00.000Z';
function response(next: string | null): RunLogsResponse {
  return { run_id: 'run_test' as RunId, entries: [], source: 'agentcore_cloudwatch', next_token: next, window_end: end };
}
it('drains empty pages beyond 25 pages with a fixed time window before advancing the watermark', async () => {
  const queries: LogPageQuery[] = [];
  const start = '2026-09-16T10:00:00.000Z';
  const pager = new RunLogPager(start);
  for (let index = 0; index < 30; index++) {
    const page = await pager.next(async (query) => {
      queries.push(query);
      return response(index < 29 ? `page-${index + 1}` : null);
    });
    expect(page.more).toBe(index < 29);
  }
  expect(queries[0]).toMatchObject({ since: start, until: undefined, nextToken: undefined });
  for (let index = 1; index < queries.length; index++) {
    expect(queries[index]).toMatchObject({ since: start, until: end, nextToken: `page-${index}` });
  }
  await pager.next(async (query) => {
    expect(query).toMatchObject({ since: '2026-09-16T11:58:00.000Z', until: undefined, nextToken: undefined });
    return response(null);
  });
});
it('retains the cursor across transient failure and surfaces a repeated cursor', async () => {
  const pager = new RunLogPager();
  await pager.next(async () => response('page-1'));
  await expect(pager.next(async () => { throw new Error('temporarily unavailable'); })).rejects.toThrow('temporarily');
  await expect(pager.next(async (query) => {
    expect(query.nextToken).toBe('page-1');
    expect(query.until).toBe(end);
    return response('page-1');
  })).rejects.toThrow('repeated a cursor');
});
