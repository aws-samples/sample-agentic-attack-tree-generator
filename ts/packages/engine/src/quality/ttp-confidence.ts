export const TTP_ACCEPTED_PRECISION_TARGET = 0.7;
export const TTP_ACCEPTANCE_POLICY_VERSION = 'similarity-margin-v1';
export const TTP_MINIMUM_ACCEPTANCE_MARGIN = 0.05;
export const TTP_STRONG_MATCH_SIMILARITY = 0.85;
export const CLOUD_TTP_BLOCKLIST = new Set(['T1014', 'T1548.002', 'T1088', 'T1553.001']);

export interface TtpCandidateMatch {
  technique_id?: unknown;
  technique_name?: unknown;
  similarity_score?: unknown;
  rank?: unknown;
  framework?: unknown;
}

export interface TtpCandidateSet {
  attack_step_id?: unknown;
  attack_step_description?: unknown;
  top_k?: unknown;
}

export interface AcceptedTtpDecision {
  confidence_kind: 'heuristic';
  attack_step_id: string;
  technique_id: string;
  technique_name: string;
  similarity_score: number;
  calibrated_confidence: number;
  confidence_policy: typeof TTP_ACCEPTANCE_POLICY_VERSION;
  accepted_precision_target: typeof TTP_ACCEPTED_PRECISION_TARGET;
  acceptance_margin: number;
  framework: string;
  abstained: false;
  reviewer_overrode_top1: false;
  reviewer_reasoning: string;
}

export interface AbstainedTtpDecision {
  confidence_kind: 'heuristic';
  attack_step_id: string;
  attack_step_description: string;
  calibrated_confidence: number;
  confidence_policy: typeof TTP_ACCEPTANCE_POLICY_VERSION;
  accepted_precision_target: typeof TTP_ACCEPTED_PRECISION_TARGET;
  acceptance_margin: number;
  abstained: true;
  abstention_reason: string;
}

export type TtpDecision = AcceptedTtpDecision | AbstainedTtpDecision;

function clampProbability(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function round4(value: number): number {
  return Math.round(value * 1e4) / 1e4;
}

function candidateMatches(value: unknown): TtpCandidateMatch[] {
  return Array.isArray(value)
    ? value.filter(
        (candidate): candidate is TtpCandidateMatch =>
          candidate !== null && typeof candidate === 'object',
      )
    : [];
}

function candidateSimilarity(candidate: TtpCandidateMatch | undefined): number {
  const value = candidate?.similarity_score;
  return typeof value === 'number' && Number.isFinite(value)
    ? clampProbability(value)
    : 0;
}

function abstain(
  candidateSet: TtpCandidateSet,
  confidence: number,
  margin: number,
  reason: string,
): AbstainedTtpDecision {
  return {
    confidence_kind: 'heuristic',
    attack_step_id:
      typeof candidateSet.attack_step_id === 'string'
        ? candidateSet.attack_step_id
        : '',
    attack_step_description:
      typeof candidateSet.attack_step_description === 'string'
        ? candidateSet.attack_step_description
        : '',
    calibrated_confidence: round4(confidence),
    confidence_policy: TTP_ACCEPTANCE_POLICY_VERSION,
    accepted_precision_target: TTP_ACCEPTED_PRECISION_TARGET,
    acceptance_margin: round4(margin),
    abstained: true,
    abstention_reason: reason,
  };
}

/**
 * Convert retrieval candidates into one explicit accepted-or-abstained decision.
 *
 * The ML threshold remains a recall-oriented candidate floor. Promotion into a
 * report is stricter: the top candidate must clear the 0.70 target and either
 * be separated from the runner-up or be a strong match. Confidence is reduced
 * by any shortfall from the required margin, making ambiguity visible instead
 * of treating raw cosine similarity as a calibrated probability.
 */
export function selectTtpDecision(
  candidateSet: TtpCandidateSet,
  excludedTechniqueIds: ReadonlySet<string> = new Set(),
): TtpDecision {
  const eligible = candidateMatches(candidateSet.top_k)
    .filter((candidate) => {
      const techniqueId = candidate.technique_id;
      return (
        typeof techniqueId === 'string' &&
        techniqueId.length > 0 &&
        !excludedTechniqueIds.has(techniqueId)
      );
    })
    .sort(
      (left, right) =>
        candidateSimilarity(right) - candidateSimilarity(left),
    );
  const top = eligible[0];
  if (top === undefined) {
    return abstain(
      candidateSet,
      0,
      0,
      'No relevant candidate was available for this attack step.',
    );
  }

  const topSimilarity = candidateSimilarity(top);
  const runnerUpSimilarity = candidateSimilarity(eligible[1]);
  const margin = Math.max(0, topSimilarity - runnerUpSimilarity);
  const ambiguityPenalty = Math.max(
    0,
    TTP_MINIMUM_ACCEPTANCE_MARGIN - margin,
  );
  const calibratedConfidence = clampProbability(
    topSimilarity - ambiguityPenalty,
  );
  if (
    calibratedConfidence < TTP_ACCEPTED_PRECISION_TARGET ||
    (margin < TTP_MINIMUM_ACCEPTANCE_MARGIN &&
      topSimilarity < TTP_STRONG_MATCH_SIMILARITY)
  ) {
    const reason =
      calibratedConfidence < TTP_ACCEPTED_PRECISION_TARGET
        ? `Heuristic match score ${round4(calibratedConfidence).toFixed(4)} is below the ${TTP_ACCEPTED_PRECISION_TARGET.toFixed(2)} acceptance threshold; this score is not empirically calibrated.`
        : `Top candidates are ambiguous: margin ${round4(margin).toFixed(4)} is below ${TTP_MINIMUM_ACCEPTANCE_MARGIN.toFixed(2)}.`;
    return abstain(candidateSet, calibratedConfidence, margin, reason);
  }

  return {
    confidence_kind: 'heuristic',
    attack_step_id:
      typeof candidateSet.attack_step_id === 'string'
        ? candidateSet.attack_step_id
        : '',
    technique_id: String(top.technique_id),
    technique_name:
      typeof top.technique_name === 'string' ? top.technique_name : '',
    similarity_score: round4(topSimilarity),
    calibrated_confidence: round4(calibratedConfidence),
    confidence_policy: TTP_ACCEPTANCE_POLICY_VERSION,
    accepted_precision_target: TTP_ACCEPTED_PRECISION_TARGET,
    acceptance_margin: round4(margin),
    framework: typeof top.framework === 'string' ? top.framework : 'attack',
    abstained: false,
    reviewer_overrode_top1: false,
    reviewer_reasoning: '',
  };
}
