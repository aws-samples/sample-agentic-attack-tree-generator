import type { RunLogsResponse } from '@threatforest/types';

export interface LogPageQuery { since?: string; until?: string; nextToken?: string; signal?: AbortSignal }
export type LogPageFetcher = (query: LogPageQuery) => Promise<RunLogsResponse>;

/** Keep the time window fixed until every CloudWatch page has been consumed. */
export class RunLogPager {
  #since: string | undefined;
  #until: string | undefined;
  #next: string | undefined;
  #seen = new Set<string>();
  constructor(since?: string) { this.#since = since; }
  async next(fetchPage: LogPageFetcher, signal?: AbortSignal): Promise<{ response: RunLogsResponse; more: boolean }> {
    const response = await fetchPage({ since: this.#since, until: this.#until, nextToken: this.#next, signal });
    this.#until ??= response.window_end ?? new Date().toISOString();
    const next = response.next_token ?? undefined;
    if (next && this.#seen.has(next)) {
      // Preserve the current cursor on failure; never silently mark a window
      // complete and skip the unconsumed pages.
      throw new Error('Log pagination repeated a cursor. Refresh logs to retry.');
    }
    if (next) {
      this.#seen.add(next);
      this.#next = next;
      return { response, more: true };
    }
    const end = Date.parse(response.window_end ?? this.#until);
    // Short execution spans arrive before a long agent invocation ends.
    // Replay overlap covers normal exporter/CloudWatch ingestion delay.
    this.#since = new Date(end - 2 * 60_000).toISOString();
    this.#until = undefined;
    this.#next = undefined;
    this.#seen.clear();
    return { response, more: false };
  }
}
