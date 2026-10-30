import type { RunId } from '@threatforest/types';
import { notFound } from './errors.js';
import type { ControlPlaneScope, RunReconstruction } from './models.js';
import type { ControlPlaneStore } from './store.js';

export async function reconstructRun(
  store: ControlPlaneStore,
  scope: ControlPlaneScope,
  runId: RunId,
): Promise<RunReconstruction> {
  const [run, settings, checkpoints, events, pendingInteractions] = await Promise.all([
    store.getRun(scope, runId),
    store.getRunSettingsSnapshot(scope, runId),
    store.listCheckpoints(scope, runId),
    store.listEvents(scope, runId),
    store.listPendingHitl(scope, runId),
  ]);
  if (run === null) {
    throw notFound(`run ${runId} was not found`);
  }
  if (settings === null) {
    throw notFound(`settings snapshot for run ${runId} was not found`);
  }
  return {
    run,
    settings,
    checkpoints,
    events,
    pending_interactions: pendingInteractions,
  };
}
