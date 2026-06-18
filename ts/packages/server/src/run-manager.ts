/**
 * Run manager — TS port of `src/server/run_manager.py`.
 *
 * Manages pipeline run lifecycle and streams progress events to WebSocket
 * clients. The Python version spawns OS threads (GIL-bound) and bridges via
 * asyncio queues; in Node the engine's `runGraph` is already async, so a run is
 * a background promise and progress events flow through a per-run async queue
 * (an EventEmitter-backed buffer that WS handlers drain).
 *
 * Pause/stop are cooperative: a ScanControl flag the executor checks at stage
 * boundaries. Resume rebuilds a RunConfig with `skip_nodes` for completed stages
 * (the engine graph + per-threat skip-if-exists handle the actual resumption).
 */
import { randomUUID } from 'node:crypto';
import {
  type RunConfig,
  type RunState,
  RunStateSchema,
} from '@threatforest/types';
import { ApplicationRegistry } from './registry.js';

/** Progress event pushed to WS clients. Mirrors run_manager.ProgressEvent.to_dict(). */
export interface ProgressEvent {
  type: string;
  stage: string;
  percentage: number;
  message: string;
  details: Record<string, unknown>;
  server_ts: number;
}

/** Cooperative pause/stop signal (port of server/scan_control.ScanControl). */
export class ScanControl {
  private _pause = false;
  private _stop = false;
  runDir: string | null = null;
  requestPause(): void {
    this._pause = true;
  }
  requestStop(): void {
    this._stop = true;
  }
  get shouldInterrupt(): boolean {
    return this._pause || this._stop;
  }
  get pauseRequested(): boolean {
    return this._pause;
  }
  get stopRequested(): boolean {
    return this._stop;
  }
}

export type OrchestratorExecutor = (
  config: RunConfig,
  onProgress: (e: ProgressEvent) => void,
  control: ScanControl,
  interactionFn: ((reason: Record<string, unknown>) => Promise<string | null>) | null,
) => Promise<{ status: string; output_dir?: string; app_id?: string; error?: string }>;

const TERMINAL = new Set(['complete', 'stopped', 'failed']);

/**
 * A simple async queue: producers push, a consumer awaits next().
 * Exported so the WS handler can name the type returned by
 * `ProgressBroadcaster.subscribe` (required for declaration emit under composite).
 *
 * Each subscriber gets its OWN AsyncQueue, so events fan out to every connection
 * instead of being stolen by whichever consumer calls next() first.
 */
export class AsyncQueue<T> {
  private buffer: T[] = [];
  private resolvers: ((v: T) => void)[] = [];
  push(item: T): void {
    const r = this.resolvers.shift();
    if (r) r(item);
    else this.buffer.push(item);
  }
  next(): Promise<T> {
    const item = this.buffer.shift();
    if (item !== undefined) return Promise.resolve(item);
    return new Promise((resolve) => this.resolvers.push(resolve));
  }
}

/** A subscription returned by {@link ProgressBroadcaster.subscribe}. */
export interface ProgressSubscription {
  /** This subscriber's private queue — independent cursor, no event stealing. */
  queue: AsyncQueue<ProgressEvent>;
  /** Detach this subscriber (call on WS close). */
  unsubscribe(): void;
}

/**
 * Per-run progress fan-out. A single producer (`publish`) broadcasts each event
 * to ALL subscribers' private queues, so multiple WS connections (or a browser
 * tab + a reconnect mid-flight) each receive the full stream independently.
 *
 * Replaces the old single shared AsyncQueue, where a second consumer would steal
 * events and any one disconnect could starve the others.
 */
export class ProgressBroadcaster {
  private readonly subscribers = new Set<AsyncQueue<ProgressEvent>>();

  publish(event: ProgressEvent): void {
    for (const q of this.subscribers) q.push(event);
  }

  subscribe(): ProgressSubscription {
    const queue = new AsyncQueue<ProgressEvent>();
    this.subscribers.add(queue);
    return {
      queue,
      unsubscribe: () => {
        this.subscribers.delete(queue);
      },
    };
  }

  get subscriberCount(): number {
    return this.subscribers.size;
  }
}

/**
 * A one-shot awaitable an agent blocks on while waiting for the user's answer
 * to an interviewer question. `submitInteractionResponse` resolves it.
 */
class PendingInteraction {
  private resolver: ((v: string | null) => void) | null = null;
  readonly promise: Promise<string | null>;
  constructor() {
    this.promise = new Promise((resolve) => {
      this.resolver = resolve;
    });
  }
  resolve(value: string | null): void {
    this.resolver?.(value);
    this.resolver = null;
  }
}

export class RunManager {
  readonly activeRuns = new Map<string, RunState>();
  private readonly broadcasters = new Map<string, ProgressBroadcaster>();
  private readonly controls = new Map<string, ScanControl>();
  private readonly history = new Map<string, ProgressEvent[]>();
  /** Per-run pending interviewer prompt, awaiting a `submitInteractionResponse`. */
  private readonly pending = new Map<string, PendingInteraction>();

  constructor(private readonly executor: OrchestratorExecutor | null = null) {}

  startRun(config: RunConfig): string {
    if (!this.executor) {
      throw new Error('No orchestrator executor configured. Provide one via new RunManager(executor).');
    }
    const runId = randomUUID().replace(/-/g, '');
    const now = new Date().toISOString();
    const state: RunState = RunStateSchema.parse({
      run_id: runId,
      status: 'pending',
      config,
      started_at: now,
    });
    this.activeRuns.set(runId, state);
    this.broadcasters.set(runId, new ProgressBroadcaster());
    this.history.set(runId, []);
    const control = new ScanControl();
    this.controls.set(runId, control);

    // Background execution (no thread needed — runGraph is async).
    void this.execute(runId, config, control);
    return runId;
  }

  private async execute(runId: string, config: RunConfig, control: ScanControl): Promise<void> {
    const state = this.activeRuns.get(runId)!;
    state.status = 'running';
    const onProgress = (e: ProgressEvent): void => {
      this.history.get(runId)?.push(e);
      this.broadcasters.get(runId)?.publish(e);
    };
    // Interviewer HITL: when the agent needs input it calls this fn, which emits
    // an `awaiting_input` event and blocks on a promise that the `/respond`
    // endpoint resolves via `submitInteractionResponse`.
    const interactionFn = async (reason: Record<string, unknown>): Promise<string | null> => {
      const p = new PendingInteraction();
      this.pending.set(runId, p);
      onProgress({
        type: 'awaiting_input',
        stage: 'interviewer',
        percentage: 0,
        message: 'Awaiting user input',
        details: reason,
        server_ts: Date.now(),
      });
      try {
        return await p.promise;
      } finally {
        this.pending.delete(runId);
      }
    };
    try {
      const result = await this.executor!(config, onProgress, control, interactionFn);
      if (result.status === 'pause') {
        state.status = 'paused';
        state.paused_at = new Date().toISOString();
        // The executor returns the run-dir ROOT here (where pause_state.json
        // lives); resumeRun reuses it. Without this, output_dir stayed null and
        // the progress-page Resume had no run dir to resume from.
        state.output_dir = result.output_dir ?? null;
      } else if (result.status === 'stop') {
        state.status = 'stopped';
        state.completed_at = new Date().toISOString();
        state.output_dir = result.output_dir ?? null;
      } else {
        state.status = result.status === 'complete' ? 'complete' : 'failed';
        state.completed_at = new Date().toISOString();
        state.output_dir = result.output_dir ?? null;
        if (result.error) state.error = result.error;
      }
    } catch (err) {
      state.status = 'failed';
      state.completed_at = new Date().toISOString();
      state.error = (err as Error).message;
    } finally {
      // Sentinel so WS consumers know the stream is done.
      onProgress({
        type: 'run_complete',
        stage: state.status,
        percentage: 100,
        message: `Run ${state.status}`,
        details: {},
        server_ts: Date.now(),
      });
    }
  }

  /**
   * Subscribe a WS connection to a run's live progress. Each call returns an
   * independent queue + unsubscribe, so concurrent connections (and reconnects)
   * each receive the full event stream rather than competing for it.
   * Throws if the run is unknown (caller falls back to history replay).
   */
  subscribeProgress(runId: string): ProgressSubscription {
    const b = this.broadcasters.get(runId);
    if (!b) throw new Error(`Unknown run_id: ${runId}`);
    return b.subscribe();
  }

  getHistory(runId: string): ProgressEvent[] {
    return this.history.get(runId) ?? [];
  }

  /** The ScanControl for a run (exposes runDir), or undefined if unknown. */
  getControl(runId: string): ScanControl | undefined {
    return this.controls.get(runId);
  }

  /**
   * Deliver a user's interviewer answer to the blocked agent thread.
   * Throws KeyError-equivalent if the run has no pending interaction.
   */
  submitInteractionResponse(runId: string, text: string | null): void {
    const p = this.pending.get(runId);
    if (!p) throw new Error(`No pending interaction for run_id: ${runId}`);
    p.resolve(text);
  }

  /**
   * Drop the per-run broadcaster ONLY once the run is terminal. History is
   * retained so late reconnects can still replay. Called by a WS connection on
   * close — but must NOT tear down a still-running stream, or other live
   * subscribers (or a reconnecting tab) would be starved. While running, a
   * disconnecting client just unsubscribes its own queue; the broadcaster lives
   * on until the run completes.
   */
  cleanupRun(runId: string): void {
    if (this.isTerminal(runId)) {
      this.broadcasters.delete(runId);
    }
  }

  pauseRun(runId: string): void {
    const state = this.activeRuns.get(runId);
    if (!state) throw new Error(`Unknown run_id: ${runId}`);
    if (state.status !== 'pending' && state.status !== 'running') {
      throw new Error(`Run ${runId} cannot be paused (status: ${state.status})`);
    }
    // A run blocked at a human-in-the-loop gate is suspended INSIDE a node and
    // yields no stream events, so the cooperative interrupt is never polled —
    // setting status='pausing' here would strand the run in 'pausing' until the
    // user answers the gate. Reject with a clear message; the user should
    // respond to (or skip) the open gate, then pause at the next boundary.
    if (this.pending.has(runId)) {
      throw new Error(
        `Run ${runId} is waiting for your input at a review step; respond to or skip it before pausing.`,
      );
    }
    state.status = 'pausing';
    this.controls.get(runId)?.requestPause();
  }

  stopRun(runId: string): void {
    const state = this.activeRuns.get(runId);
    if (!state) throw new Error(`Unknown run_id: ${runId}`);
    if (state.status === 'paused') {
      state.status = 'stopped';
      state.completed_at = new Date().toISOString();
      return;
    }
    if (!['pending', 'running', 'pausing'].includes(state.status)) {
      throw new Error(`Run ${runId} cannot be stopped (status: ${state.status})`);
    }
    // Same gate caveat as pauseRun: a run blocked awaiting input can't honor a
    // cooperative stop until the gate is resolved. Reject clearly.
    if (this.pending.has(runId)) {
      throw new Error(
        `Run ${runId} is waiting for your input at a review step; respond to or skip it before stopping.`,
      );
    }
    this.controls.get(runId)?.requestStop();
  }

  /**
   * Resume a paused/stopped run by starting a fresh run that reuses the run dir
   * and skips the nodes that already completed. For a paused/stopped run,
   * `state.output_dir` is the run-dir ROOT (the executor returns runDir, not
   * runDir/output, on interrupt), which is where `pause_state.json` lives. We
   * read it from disk (the durable source of truth that survives a process
   * restart) to recover `completed_nodes` → `skip_nodes`, so the resumed run
   * replaces those stages with no-op skip nodes and continues from the first
   * not-yet-completed node.
   */
  resumeRun(runId: string): string {
    const state = this.activeRuns.get(runId);
    if (!state) throw new Error(`Unknown run_id: ${runId}`);
    if (state.status !== 'paused' && state.status !== 'stopped') {
      throw new Error(`Run ${runId} is not resumable (status: ${state.status})`);
    }
    const runDir = state.output_dir ?? state.config.resume_run_dir;
    if (!runDir) {
      throw new Error(`Run ${runId} has no run directory to resume from`);
    }
    const pause = new ApplicationRegistry().readPauseState(runDir);
    const resumeConfig: RunConfig = {
      ...state.config,
      resume_run_dir: runDir,
      skip_nodes: pause?.completed_nodes ?? state.config.skip_nodes ?? [],
    };
    return this.startRun(resumeConfig);
  }

  isTerminal(runId: string): boolean {
    const s = this.activeRuns.get(runId);
    return !!s && TERMINAL.has(s.status);
  }
}
