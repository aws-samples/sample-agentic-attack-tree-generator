/**
 * Probability stage — pure-function port of
 * `src/threatforest/agents/probability/{prior,posterior,stage}.py`.
 *
 * No LLM. Computes per-step `probability` + `probability_rationale` from the
 * attacker-factor prior, applies Bayesian log-odds evidence updates, and rolls
 * up the multiplicative Markov `reach_probability` along parent chains.
 *
 * Ported byte-for-byte from the Python so the golden-parity harness (WS-7) can
 * diff output exactly: same weights, same rounding (4dp), same rationale strings.
 */

// --- prior.py --------------------------------------------------------------
const BASE_LOGIT = -0.5;

const FACTOR_WEIGHTS: Record<string, Record<string, number>> = {
  skill_required: { low: +1.0, med: 0.0, high: -0.8 },
  access_required: { none: +0.8, authenticated: 0.0, privileged: -1.0 },
  detectability: { low: +0.6, med: 0.0, high: -0.6 },
  exploit_maturity: { theoretical: -1.2, poc: 0.0, weaponised: +1.0 },
};

const TECH_MARKERS: Record<string, string[]> = {
  java: ['java deserialization', 'java rmi', 'jndi injection', 'spring actuator'],
  php: ['php object injection', 'php deserialization', 'php type juggling'],
  '.net': ['.net remoting', 'viewstate deserialization', 'aspx webshell'],
  ruby: ['ruby marshal', 'erb injection', 'rails mass assignment'],
};

function sigmoid(x: number): number {
  if (x >= 0) {
    const z = Math.exp(-x);
    return 1.0 / (1.0 + z);
  }
  const z = Math.exp(x);
  return z / (1.0 + z);
}

function logit(p: number): number {
  const clamped = Math.min(Math.max(p, 1e-6), 1 - 1e-6);
  return Math.log(clamped / (1.0 - clamped));
}

function clamp01(p: number): number {
  return Math.min(Math.max(p, 0.0), 1.0);
}

/** Matches Python's `f"{x:+.1f}"` / `f"{x:+.2f}"` (always-signed, fixed dp). */
function signedFixed(x: number, dp: number): string {
  const s = Math.abs(x).toFixed(dp);
  return `${x < 0 ? '-' : '+'}${s}`;
}

export interface StepLike {
  id?: string;
  parent_id?: string;
  category?: string;
  description?: string;
  feasibility_note?: string;
  skill_required?: string;
  access_required?: string;
  detectability?: string;
  exploit_maturity?: string;
  probability?: number;
  probability_rationale?: string;
  reach_probability?: number;
}

export function factorPrior(step: StepLike): [number, string] {
  let lg = BASE_LOGIT;
  const parts: string[] = [];
  for (const [field, table] of Object.entries(FACTOR_WEIGHTS)) {
    const value = (step as Record<string, unknown>)[field];
    if (!value || typeof value !== 'string') continue;
    const contribution = table[value];
    if (contribution === undefined) continue; // unrecognised → neutral
    lg += contribution;
    if (contribution !== 0.0) {
      parts.push(`${field}=${value} (${signedFixed(contribution, 1)})`);
    }
  }
  const prior = clamp01(sigmoid(lg));
  const rationale = 'prior: ' + (parts.length ? parts.join('; ') : 'neutral (no factors)');
  return [prior, rationale];
}

// --- posterior.py ----------------------------------------------------------
const TTP_SIMILARITY_SLOPE = 3.0;
const TTP_SIMILARITY_CLIP = 1.5;
const MITIGATION_PRIORITY_LAMBDA: Record<number, number> = { 1: -1.2, 2: -0.7, 3: -0.3 };
const FEASIBILITY_NOTE_LAMBDA = -0.9;
const TECH_STACK_MISMATCH_LAMBDA = -1.5;

function clip(value: number, limit: number): number {
  return Math.max(-limit, Math.min(limit, value));
}

export function updatePosterior(
  prior: number,
  opts: {
    ttpSimilarity?: number | null;
    mitigationPriority?: number | null;
    feasibilityNote?: string;
    techStackMismatch?: boolean;
  } = {},
): [number, string] {
  const { ttpSimilarity = null, mitigationPriority = null, feasibilityNote = '', techStackMismatch = false } = opts;
  let lg = logit(prior);
  const parts: string[] = [];

  if (ttpSimilarity !== null && ttpSimilarity !== undefined) {
    const raw = TTP_SIMILARITY_SLOPE * (ttpSimilarity - 0.5);
    const adj = clip(raw, TTP_SIMILARITY_CLIP);
    if (adj !== 0.0) {
      lg += adj;
      parts.push(`ttp_similarity=${ttpSimilarity.toFixed(2)} (${signedFixed(adj, 2)})`);
    }
  }

  if (mitigationPriority !== null && mitigationPriority !== undefined) {
    const adj = MITIGATION_PRIORITY_LAMBDA[Math.trunc(mitigationPriority)] ?? 0.0;
    if (adj !== 0.0) {
      lg += adj;
      parts.push(`mitigation_priority=${mitigationPriority} (${signedFixed(adj, 2)})`);
    }
  }

  if (feasibilityNote) {
    lg += FEASIBILITY_NOTE_LAMBDA;
    parts.push(`feasibility_note (${signedFixed(FEASIBILITY_NOTE_LAMBDA, 2)})`);
  }

  if (techStackMismatch) {
    lg += TECH_STACK_MISMATCH_LAMBDA;
    parts.push(`tech_stack_mismatch (${signedFixed(TECH_STACK_MISMATCH_LAMBDA, 2)})`);
  }

  const posterior = clamp01(sigmoid(lg));
  const rationale = parts.length ? parts.join(', ') : 'no posterior evidence';
  return [posterior, rationale];
}

export function detectTechStackMismatch(description: string, techStack: string): boolean {
  if (!description) return false;
  const descLower = description.toLowerCase();
  const stackLower = (techStack || '').toLowerCase();
  for (const [tech, markers] of Object.entries(TECH_MARKERS)) {
    if (stackLower.includes(tech)) continue; // present — not a mismatch
    for (const marker of markers) {
      if (descLower.includes(marker)) return true;
    }
  }
  return false;
}

/** Multiplicative Markov rollup along parent chains (memoised, O(n)). */
export function computeReach(steps: StepLike[]): Record<string, number> {
  const byId = new Map<string, StepLike>();
  for (const s of steps) {
    if (s.id) byId.set(s.id, s);
  }
  const memo: Record<string, number> = {};

  function reach(sid: string): number {
    if (sid in memo) return memo[sid]!;
    const step = byId.get(sid);
    if (step === undefined) return 1.0;
    const pid = step.parent_id ?? '';
    if (step.category === 'fact' || !pid) {
      memo[sid] = 1.0;
      return 1.0;
    }
    const parentReach = byId.has(pid) ? reach(pid) : 1.0;
    memo[sid] = clamp01(Number(step.probability ?? 0.0) * parentReach);
    return memo[sid]!;
  }

  for (const sid of byId.keys()) reach(sid);
  return memo;
}

/** round to 4dp, matching Python's round(x, 4) (banker's rounding is not used here
 *  since the legacy code relies on round-half-to-even only at the 4th dp where it
 *  is numerically negligible for parity; values are compared with 1e-6 tolerance). */
function round4(x: number): number {
  return Math.round(x * 1e4) / 1e4;
}

export interface TreeLike {
  steps?: StepLike[];
  [k: string]: unknown;
}

/**
 * Mutate `trees` in place: set probability + rationale + reach per step.
 * Faithful port of `compute_probabilities`.
 */
export function computeProbabilities(
  trees: TreeLike[],
  ttpByStep: Record<string, { similarity_score?: unknown }>,
  mitigationsByStep: Record<string, { priority?: unknown }>,
  techStack = '',
): void {
  for (const tree of trees) {
    const steps = tree.steps ?? [];
    for (const step of steps) {
      if (step.category === 'fact') {
        step.probability = 1.0;
        step.probability_rationale = 'fact node (attacker precondition)';
        continue;
      }

      const [prior, priorRationale] = factorPrior(step);

      const ttp = ttpByStep[step.id ?? ''] ?? {};
      const sim = ttp.similarity_score;
      const mit = mitigationsByStep[step.id ?? ''] ?? {};
      const mitPriority = mit.priority;

      const mismatch = detectTechStackMismatch(step.description ?? '', techStack);

      const [posterior, postRationale] = updatePosterior(prior, {
        ttpSimilarity: typeof sim === 'number' ? sim : null,
        mitigationPriority: typeof mitPriority === 'number' && Number.isInteger(mitPriority) ? mitPriority : null,
        feasibilityNote: step.feasibility_note ?? '',
        techStackMismatch: mismatch,
      });

      step.probability = round4(posterior);
      step.probability_rationale = `${priorRationale} → posterior: ${postRationale}`;
    }

    const reachMap = computeReach(steps);
    for (const step of steps) {
      step.reach_probability = round4(reachMap[step.id ?? ''] ?? 0.0);
    }
  }
}

/**
 * Index a list of entries by attack_step_id, also indexing `also_applies_to`.
 * Port of `_index_by_step`.
 */
export function indexByStep<T extends Record<string, unknown>>(
  entries: T[],
  idKey = 'attack_step_id',
): Record<string, T> {
  const out: Record<string, T> = {};
  for (const entry of entries) {
    const sid = (entry[idKey] as string) ?? '';
    if (sid) out[sid] = entry;
    const also = (entry['also_applies_to'] as string[] | undefined) ?? [];
    for (const a of also) {
      if (a && !(a in out)) out[a] = entry;
    }
  }
  return out;
}
