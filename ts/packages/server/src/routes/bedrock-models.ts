/**
 * Live Bedrock model discovery — `GET /api/config/bedrock/models`.
 *
 * Replaces the hardcoded model tables that the Configure page and the CLI
 * wizard each carried (and which drifted from the real catalogue: Opus 5,
 * Sonnet 5 and Fable 5 were all invocable while absent from both lists).
 *
 * WHY TWO AWS APIS ARE MERGED
 * ---------------------------
 * The ids ThreatForest actually runs on are cross-region inference profiles
 * (`global.anthropic.claude-opus-4-8`), and those DO NOT appear in
 * `ListFoundationModels` — that returns only base ids (`anthropic.claude-…`).
 * The profiles live in `ListInferenceProfiles`. Calling just the former yields a
 * list where none of the configured ids appear, so every cross-region model
 * silently vanishes from the dropdown; calling just the latter loses the
 * single-region base models and all lifecycle metadata. Hence: query both, then
 * merge on id.
 *
 * FAILURE POLICY
 * --------------
 * Discovery is a convenience, never a gate. Missing credentials, a deploy role
 * without `bedrock:ListFoundationModels`, or an offline demo machine must not
 * leave an operator staring at an empty dropdown, so every failure path falls
 * back to the static list and reports `source: 'fallback'` with a warning the UI
 * renders. The Model ID field also stays free-text, so a brand-new model id can
 * always be typed regardless of what discovery returns.
 *
 * A NOTE ON WHAT THIS CANNOT DO
 * -----------------------------
 * Neither API reports per-account entitlement, so a listed model may still 403
 * on invoke. There is no pre-flight check short of actually calling the model,
 * so "listed" means "exists and is ON_DEMAND-invocable in this region", not
 * "this account is entitled to it".
 */
import {
  BedrockClient,
  ListFoundationModelsCommand,
  ListInferenceProfilesCommand,
  type FoundationModelSummary,
  type InferenceProfileSummary,
} from '@aws-sdk/client-bedrock';
import { Router, type Request, type Response } from 'express';
import type { BedrockModel, BedrockModelsResponse } from '@threatforest/types';

export const bedrockModelsRouter: Router = Router();

/**
 * Static last-resort list, used only when live discovery fails. Intentionally
 * short — it exists so the UI stays usable, not to mirror the catalogue (that is
 * the job this module removes).
 */
const FALLBACK_MODEL_IDS = [
  'global.anthropic.claude-opus-4-8',
  'global.anthropic.claude-opus-4-7',
  'global.anthropic.claude-sonnet-4-6',
  'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
  'global.anthropic.claude-haiku-4-5-20251001-v1:0',
  'global.amazon.nova-2-lite-v1:0',
];

/**
 * Providers whose models the pipeline is actually tuned for. The agent prompts
 * and the temperature-deprecation handling in the engine's `providers.ts` are
 * Claude-shaped, so a Qwen or Mistral id will run but tends to produce weak
 * threat models. These are flagged `recommended` so the UI can group them —
 * NOT filtered out, since the caller may deliberately want another provider.
 */
const RECOMMENDED_PROVIDERS = new Set(['anthropic', 'amazon']);

/** In-memory cache. The catalogue changes on the order of weeks. */
const CACHE_TTL_MS = 60 * 60 * 1000;
interface CacheEntry {
  at: number;
  payload: BedrockModelsResponse;
}
const cache = new Map<string, CacheEntry>();

/** Exposed for tests and for a future explicit "refresh" affordance. */
export function clearBedrockModelCache(): void {
  cache.clear();
}

/**
 * Region for the control-plane calls. Mirrors the engine's resolution order so
 * discovery targets the same region the pipeline will invoke against.
 */
function resolveRegion(): string {
  return process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION ?? 'us-east-1';
}

/**
 * Derive a readable label from a model id, used when AWS gives us no
 * `modelName` (inference-profile summaries often carry a terse one).
 *
 * `global.anthropic.claude-opus-4-8` -> `Claude Opus 4 8`
 */
function labelFromId(id: string): string {
  const withoutScope = id.replace(/^(global|us|eu|apac)\./, '');
  const withoutProvider = withoutScope.replace(/^[a-z0-9-]+\./, '');
  const withoutVersion = withoutProvider.replace(/-v\d+(:\d+)?$/, '').replace(/:\d+$/, '');
  const words = withoutVersion
    .split(/[-_]/)
    .filter((w) => !/^\d{8}$/.test(w)) // drop date stamps like 20251101
    .map((w) => (w.length <= 2 ? w : w.charAt(0).toUpperCase() + w.slice(1)));
  return words.join(' ').trim() || id;
}

/** `global.anthropic.claude-…` -> `global`; base ids -> null. */
function scopeOf(id: string): string | null {
  const m = /^(global|us|eu|apac)\./.exec(id);
  return m ? (m[1] ?? null) : null;
}

/** `global.anthropic.claude-opus-4-8` -> `anthropic.claude-opus-4-8`. */
function baseIdOf(id: string): string {
  return id.replace(/^(global|us|eu|apac)\./, '');
}

/** `global.anthropic.claude-…` -> `anthropic`. */
function providerKeyOf(id: string): string {
  const withoutScope = id.replace(/^(global|us|eu|apac)\./, '');
  const m = /^([a-z0-9-]+)\./.exec(withoutScope);
  return m?.[1] ?? '';
}

function decorateLabel(base: string, id: string): string {
  const scope = scopeOf(id);
  return scope ? `${base} (${scope})` : base;
}

function toLifecycle(status: string | undefined): BedrockModel['lifecycle'] {
  if (status === 'ACTIVE' || status === 'LEGACY') return status;
  return 'UNKNOWN';
}

/**
 * Map a `ListFoundationModels` entry. Returns null for models this pipeline
 * cannot drive: no TEXT output, or not invocable on demand.
 */
function fromFoundationModel(m: FoundationModelSummary): BedrockModel | null {
  const id = m.modelId;
  if (!id) return null;
  if (!(m.outputModalities ?? []).includes('TEXT')) return null;

  // ON_DEMAND = callable directly. INFERENCE_PROFILE-only base ids are NOT
  // callable as-is (they must be reached via their profile id, which the
  // ListInferenceProfiles pass contributes separately), so drop them here to
  // avoid offering an id that always fails with a validation error.
  //
  // Compared as raw strings on purpose: the service returns values the SDK's
  // `InferenceType` union does not yet include — "INFERENCE_PROFILE" is absent
  // from it while being what the API actually reports for, say,
  // anthropic.claude-opus-4-8. Widening to string[] keeps this correct as AWS
  // adds inference types ahead of the typings.
  const inferenceTypes: readonly string[] = m.inferenceTypesSupported ?? [];
  if (!inferenceTypes.includes('ON_DEMAND')) return null;

  const providerKey = providerKeyOf(id);
  return {
    id,
    label: decorateLabel(m.modelName?.trim() || labelFromId(id), id),
    provider: m.providerName?.trim() || 'Unknown',
    lifecycle: toLifecycle(m.modelLifecycle?.status),
    end_of_life: m.modelLifecycle?.endOfLifeTime?.toISOString() ?? null,
    is_inference_profile: false,
    recommended: RECOMMENDED_PROVIDERS.has(providerKey),
  };
}

/**
 * Map a `ListInferenceProfiles` entry. Only ACTIVE profiles are offered —
 * anything else is not invocable right now.
 */
function fromInferenceProfile(p: InferenceProfileSummary): BedrockModel | null {
  const id = p.inferenceProfileId;
  if (!id) return null;
  // Widened to string for the same reason as inferenceTypesSupported above: the
  // SDK narrows this to the single literal 'ACTIVE', so any future status value
  // would not compare cleanly against the typed field.
  const status: string | undefined = p.status;
  if (status !== undefined && status !== 'ACTIVE') return null;

  const providerKey = providerKeyOf(id);
  return {
    id,
    label: decorateLabel(p.inferenceProfileName?.trim() || labelFromId(id), id),
    // Profile summaries carry no provider field; derive it from the id so the
    // dropdown can still group by vendor.
    provider: providerKey ? providerKey.charAt(0).toUpperCase() + providerKey.slice(1) : 'Unknown',
    lifecycle: 'UNKNOWN',
    end_of_life: null,
    is_inference_profile: true,
    recommended: RECOMMENDED_PROVIDERS.has(providerKey),
  };
}

/** Sort: recommended first, then ACTIVE before LEGACY, then label. */
function compareModels(a: BedrockModel, b: BedrockModel): number {
  if (a.recommended !== b.recommended) return a.recommended ? -1 : 1;
  const legacyA = a.lifecycle === 'LEGACY' ? 1 : 0;
  const legacyB = b.lifecycle === 'LEGACY' ? 1 : 0;
  if (legacyA !== legacyB) return legacyA - legacyB;
  return a.label.localeCompare(b.label);
}

function buildFallback(region: string, warning: string): BedrockModelsResponse {
  const models = FALLBACK_MODEL_IDS.map((id): BedrockModel => {
    const providerKey = providerKeyOf(id);
    return {
      id,
      label: decorateLabel(labelFromId(id), id),
      provider: providerKey ? providerKey.charAt(0).toUpperCase() + providerKey.slice(1) : 'Unknown',
      lifecycle: 'UNKNOWN',
      end_of_life: null,
      is_inference_profile: scopeOf(id) !== null,
      recommended: RECOMMENDED_PROVIDERS.has(providerKey),
    };
  });
  return { models, source: 'fallback', warning, region };
}

/** Injection seam so tests can exercise the merge without hitting AWS. */
export interface BedrockCatalogueClient {
  listFoundationModels(): Promise<FoundationModelSummary[]>;
  listInferenceProfiles(): Promise<InferenceProfileSummary[]>;
}

function makeAwsClient(region: string): BedrockCatalogueClient {
  const client = new BedrockClient({ region });
  return {
    async listFoundationModels(): Promise<FoundationModelSummary[]> {
      const out = await client.send(
        new ListFoundationModelsCommand({ byOutputModality: 'TEXT' }),
      );
      return out.modelSummaries ?? [];
    },
    async listInferenceProfiles(): Promise<InferenceProfileSummary[]> {
      // Paginate: the profile list already exceeds a single page in some regions.
      const summaries: InferenceProfileSummary[] = [];
      let nextToken: string | undefined;
      do {
        const out = await client.send(
          new ListInferenceProfilesCommand({
            maxResults: 100,
            ...(nextToken ? { nextToken } : {}),
          }),
        );
        summaries.push(...(out.inferenceProfileSummaries ?? []));
        nextToken = out.nextToken;
      } while (nextToken);
      return summaries;
    },
  };
}

/**
 * Discover invocable Bedrock text models, merging both catalogue APIs.
 *
 * Partial failure is tolerated: if one API errors but the other succeeds the
 * result is still `live` (with a warning), because a dropdown missing the
 * base-model tail is far more useful than no dropdown at all. Only a total
 * failure falls back to the static list.
 */
export async function discoverBedrockModels(
  region: string,
  client: BedrockCatalogueClient = makeAwsClient(region),
): Promise<BedrockModelsResponse> {
  const [fmResult, ipResult] = await Promise.allSettled([
    client.listFoundationModels(),
    client.listInferenceProfiles(),
  ]);

  if (fmResult.status === 'rejected' && ipResult.status === 'rejected') {
    const reason =
      fmResult.reason instanceof Error ? fmResult.reason.message : String(fmResult.reason);
    return buildFallback(
      region,
      `Could not reach the Bedrock model catalogue (${reason}). ` +
        'Showing a built-in list — you can still type any model id directly.',
    );
  }

  // Index every base model's lifecycle first (including ones dropped from the
  // offered list for not being ON_DEMAND) so profiles can inherit it below.
  const lifecycleByBaseId = new Map<
    string,
    { lifecycle: BedrockModel['lifecycle']; endOfLife: string | null }
  >();
  if (fmResult.status === 'fulfilled') {
    for (const m of fmResult.value) {
      if (!m.modelId) continue;
      lifecycleByBaseId.set(m.modelId, {
        lifecycle: toLifecycle(m.modelLifecycle?.status),
        endOfLife: m.modelLifecycle?.endOfLifeTime?.toISOString() ?? null,
      });
    }
  }

  // Inference profiles are added first so that when a profile and a base model
  // collide on id, the profile's richer scoping wins.
  const byId = new Map<string, BedrockModel>();
  if (ipResult.status === 'fulfilled') {
    for (const p of ipResult.value) {
      const model = fromInferenceProfile(p);
      if (!model) continue;
      // ListInferenceProfiles carries no lifecycle, so a `global.*` id — i.e.
      // exactly what this pipeline runs on — would always report UNKNOWN and
      // never warn about an upcoming EOL. Inherit it from the underlying base
      // model, which does carry it.
      const inherited = lifecycleByBaseId.get(baseIdOf(model.id));
      if (inherited) {
        model.lifecycle = inherited.lifecycle;
        model.end_of_life = inherited.endOfLife;
      }
      byId.set(model.id, model);
    }
  }
  if (fmResult.status === 'fulfilled') {
    for (const m of fmResult.value) {
      const model = fromFoundationModel(m);
      if (model && !byId.has(model.id)) byId.set(model.id, model);
    }
  }

  const warnings: string[] = [];
  if (fmResult.status === 'rejected') {
    warnings.push('base foundation models could not be listed');
  }
  if (ipResult.status === 'rejected') {
    warnings.push(
      'cross-region inference profiles could not be listed (global.* / us.* ids are missing)',
    );
  }

  const models = [...byId.values()].sort(compareModels);

  // A successful call that yields nothing is a fallback case in practice: an
  // empty dropdown is indistinguishable from a broken page for the operator.
  if (models.length === 0) {
    return buildFallback(
      region,
      'The Bedrock catalogue returned no invocable text models for this region. ' +
        'Showing a built-in list — you can still type any model id directly.',
    );
  }

  return {
    models,
    source: 'live',
    warning: warnings.length > 0 ? `Partial results: ${warnings.join('; ')}.` : null,
    region,
  };
}

bedrockModelsRouter.get(
  '/config/bedrock/models',
  async (req: Request, res: Response): Promise<void> => {
    const region = typeof req.query.region === 'string' && req.query.region.trim() !== ''
      ? req.query.region.trim()
      : resolveRegion();
    const refresh = req.query.refresh === 'true';

    const hit = cache.get(region);
    if (!refresh && hit && Date.now() - hit.at < CACHE_TTL_MS) {
      res.json(hit.payload);
      return;
    }

    // discoverBedrockModels resolves rather than throws for expected failures;
    // this guard covers anything unexpected (e.g. a client constructor throwing
    // on a malformed region) so the endpoint never 500s the Configure page.
    let payload: BedrockModelsResponse;
    try {
      payload = await discoverBedrockModels(region);
    } catch (err) {
      payload = buildFallback(
        region,
        `Model discovery failed unexpectedly (${err instanceof Error ? err.message : String(err)}). ` +
          'Showing a built-in list — you can still type any model id directly.',
      );
    }

    // Only cache live results, so a transient credential problem does not pin a
    // fallback list for an hour.
    if (payload.source === 'live') cache.set(region, { at: Date.now(), payload });
    res.json(payload);
  },
);
