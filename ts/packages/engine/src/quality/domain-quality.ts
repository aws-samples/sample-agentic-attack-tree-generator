import {
  TTP_ACCEPTED_PRECISION_TARGET,
  TTP_ACCEPTANCE_POLICY_VERSION,
} from './ttp-confidence.js';
import type { EvidenceResolver } from './evidence.js';

type Json = Record<string, unknown>;

export interface DomainQualityInput {
  threats?: readonly Json[];
  attackTrees: readonly Json[];
  ttpMappings: readonly Json[];
  mitigations: readonly Json[];
  resolveEvidence?: EvidenceResolver;
}

export interface DomainQualityReport {
  schemaVersion: '1.1.0';
  gatePassed: boolean;
  issues: readonly string[];
  counts: {
    threats: number;
    attackSteps: number;
    ttpDecisions: number;
    acceptedTtpMappings: number;
    ttpAbstentions: number;
    mitigationTargets: number;
    mitigatedTargets: number;
    evidencedTargets: number;
  };
  metrics: {
    ttpDecisionCoverage: number;
    ttpAcceptedCoverage: number;
    ttpAbstentionRate: number;
    meanAcceptedConfidence: number | null;
    mitigationCoverage: number | null;
    mitigationEvidenceCoverage: number | null;
  };
  policy: {
    ttpAcceptedPrecisionTarget: typeof TTP_ACCEPTED_PRECISION_TARGET;
    ttpAcceptancePolicy: typeof TTP_ACCEPTANCE_POLICY_VERSION;
  };
}

interface AcceptedTarget {
  stepId: string;
  techniqueId: string;
}

interface TtpDecisionAnalysis {
  issues: string[];
  uniqueStepIds: Set<string>;
  decisionsByStep: Map<string, Json[]>;
}

function records(value: unknown): Json[] {
  return Array.isArray(value)
    ? value.filter(
        (entry): entry is Json =>
          entry !== null && typeof entry === 'object' && !Array.isArray(entry),
      )
    : [];
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function finiteProbability(value: unknown): number | null {
  return typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
    ? value
    : null;
}

function ratio(numerator: number, denominator: number, emptyValue: number): number {
  return denominator === 0 ? emptyValue : numerator / denominator;
}

export function hasUsableMitigationEvidence(value: unknown, resolveEvidence?: EvidenceResolver): boolean {
  return records(value).some(
    (entry) =>
      text(entry['source_type']).length > 0 &&
      text(entry['source_ref']).length > 0 &&
      text(entry['excerpt']).length > 0 &&
      text(entry['relevance']).length > 0 &&
      resolveEvidence?.(entry) != null,
  );
}

function acceptedTargets(mappings: readonly Json[]): AcceptedTarget[] {
  return mappings.flatMap((mapping) => {
    if (mapping['abstained'] === true) {
      return [];
    }
    const stepId = text(mapping['attack_step_id']);
    const techniqueId = text(mapping['technique_id']);
    return stepId && techniqueId ? [{ stepId, techniqueId }] : [];
  });
}

function mitigationCoverageForTarget(
  target: AcceptedTarget,
  mitigations: readonly Json[],
  resolveEvidence?: EvidenceResolver,
): { covered: boolean; evidenced: boolean } {
  const applicable = mitigations.filter((mitigation) => {
    const ids = new Set([
      text(mitigation['attack_step_id']),
      ...recordsOrStrings(mitigation['also_applies_to']),
    ]);
    return (
      ids.has(target.stepId) &&
      text(mitigation['technique_id']) === target.techniqueId
    );
  });
  return {
    covered: applicable.length > 0,
    evidenced: applicable.some((mitigation) =>
      hasUsableMitigationEvidence(mitigation['evidence'], resolveEvidence),
    ),
  };
}

function recordsOrStrings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map(text).filter((entry) => entry.length > 0)
    : [];
}

export function findMitigationQualityIssues(
  mappings: readonly Json[],
  mitigations: readonly Json[],
  options: { attackTrees?: readonly Json[]; resolveEvidence?: EvidenceResolver } = {},
): string[] {
  const issues: string[] = [];
  const targets = mitigationTargets(mappings, options.attackTrees);
  const targetIds = new Set(targets.map((target) => target.stepId));

  mitigations.forEach((mitigation, index) => {
    const stepId = text(mitigation['attack_step_id']);
    if (!stepId) {
      issues.push(`Mitigation ${index}: missing attack_step_id`);
    } else if (!targetIds.has(stepId)) {
      issues.push(`${stepId}: mitigation references an unknown attack step`);
    }
    for (const id of [stepId, ...recordsOrStrings(mitigation['also_applies_to'])]) {
      const target = targets.find((candidate) => candidate.stepId === id);
      if (target === undefined) {
        issues.push(`${id}: mitigation references an unknown attack step`);
      } else if (text(mitigation['technique_id']) !== target.techniqueId) {
        issues.push(`${id}: mitigation technique must match its TTP decision (empty for abstentions)`);
      }
    }
    if (!text(mitigation['mitigation_text'])) {
      issues.push(`${stepId || `Mitigation ${index}`}: empty mitigation_text`);
    }
    if (!hasUsableMitigationEvidence(mitigation['evidence'], options.resolveEvidence)) {
      issues.push(`${stepId || `Mitigation ${index}`}: no usable evidence verified against current source`);
    }
    const rawEvidence = mitigation['evidence'];
    if (!Array.isArray(rawEvidence) || records(rawEvidence).length !== rawEvidence.length) {
      issues.push(`${stepId || `Mitigation ${index}`}: evidence must be an array of objects`);
    }
    for (const entry of records(mitigation['evidence'])) {
      if (!hasUsableMitigationEvidence([entry], options.resolveEvidence)) {
        issues.push(`${stepId || `Mitigation ${index}`}: unverifiable evidence ${text(entry['source_ref'])}`);
      }
    }
  });

  for (const target of targets) {
    const coverage = mitigationCoverageForTarget(target, mitigations, options.resolveEvidence);
    if (!coverage.covered) {
      issues.push(
        `${target.stepId}: no mitigation covers attack step${target.techniqueId ? ` (${target.techniqueId})` : ' (TTP abstained)'}`,
      );
    } else if (!coverage.evidenced) {
      issues.push(`${target.stepId}: mitigation coverage has no usable evidence`);
    }
  }
  return [...new Set(issues)];
}

function mitigationTargets(mappings: readonly Json[], attackTrees?: readonly Json[]): AcceptedTarget[] {
  const ids = attackTrees === undefined
    ? mappings.map((mapping) => text(mapping['attack_step_id']))
    : attackTrees.flatMap((tree) => records(tree['steps']).map((step) => text(step['id'])));
  return [...new Set(ids.filter(Boolean))].map((stepId) => {
    const mapping = mappings.find((item) => text(item['attack_step_id']) === stepId);
    return { stepId, techniqueId: mapping?.['abstained'] === true ? '' : text(mapping?.['technique_id']) };
  });
}

export function findAttackTreeQualityIssues(attackTrees: readonly Json[], threats?: readonly Json[]): string[] {
  const issues: string[] = [];
  const threatIds = new Set(threats?.map((threat) => text(threat['id'])));
  if (threats !== undefined && threatIds.size !== threats.length) {
    issues.push('Threats contain duplicate IDs');
  }
  const coveredThreats = new Set<string>();
  const treeIds = new Set<string>();
  for (const tree of attackTrees) {
    const treeId = text(tree['id']);
    const threatId = text(tree['threat_id']);
    if (!treeId || treeIds.has(treeId)) issues.push('Attack trees contain missing or duplicate tree IDs');
    treeIds.add(treeId);
    if (!threatId || (threats !== undefined && !threatIds.has(threatId))) {
      issues.push(`${treeId}: tree references an unknown threat`);
    }
    coveredThreats.add(threatId);
    const steps = records(tree['steps']);
    if (!Array.isArray(tree['steps']) || steps.length !== tree['steps'].length) {
      issues.push(`${treeId}: steps must be an array of objects`);
    }
    if (!steps.length) issues.push(`${treeId}: tree has no attack steps`);
    const byId = new Map(steps.map((step) => [text(step['id']), step]));
    if (byId.has('') || byId.size !== steps.length) {
      issues.push(`${treeId}: attack steps have missing or duplicate IDs`);
    }
    const roots = steps.filter((step) => step['parent_id'] === '');
    if (roots.length !== 1) issues.push(`${treeId}: tree must have exactly one root with empty parent_id`);
    for (const step of steps) {
      const id = text(step['id']);
      if (typeof step['parent_id'] !== 'string') issues.push(`${id}: missing parent_id`);
      const visited = new Set<string>([id]);
      let parent = text(step['parent_id']);
      while (parent) {
        if (!byId.has(parent)) {
          issues.push(`${id}: parent ${parent} is outside its attack tree`);
          break;
        }
        if (visited.has(parent)) {
          issues.push(`${id}: attack tree contains a cycle`);
          break;
        }
        visited.add(parent);
        parent = text(byId.get(parent)?.['parent_id']);
      }
    }
  }
  for (const id of threatIds) {
    if (!id) issues.push('Threat has no ID');
    else if (!coveredThreats.has(id)) issues.push(`${id}: threat has no attack tree`);
  }
  return [...new Set(issues)];
}

function analyzeTtpDecisions(
  attackTrees: readonly Json[],
  mappings: readonly Json[],
): TtpDecisionAnalysis {
  const issues: string[] = [];
  const stepIds: string[] = [];
  for (const [treeIndex, tree] of attackTrees.entries()) {
    for (const [stepIndex, step] of records(tree['steps']).entries()) {
      const stepId = text(step['id']);
      if (!stepId) {
        issues.push(`Attack tree ${treeIndex} step ${stepIndex}: missing step ID`);
      } else {
        stepIds.push(stepId);
      }
    }
  }
  const uniqueStepIds = new Set(stepIds);
  if (uniqueStepIds.size !== stepIds.length) {
    issues.push('Attack trees contain duplicate step IDs');
  }

  const decisionsByStep = new Map<string, Json[]>();
  for (const [index, mapping] of mappings.entries()) {
    const stepId = text(mapping['attack_step_id']);
    if (!stepId) {
      issues.push(`TTP decision ${index}: missing attack_step_id`);
      continue;
    }
    const decisions = decisionsByStep.get(stepId) ?? [];
    decisions.push(mapping);
    decisionsByStep.set(stepId, decisions);
    if (!uniqueStepIds.has(stepId)) {
      issues.push(`${stepId}: TTP decision references an unknown attack step`);
    }

    const confidence = finiteProbability(mapping['calibrated_confidence']);
    if (confidence === null) {
      issues.push(`${stepId}: TTP decision is missing calibrated confidence`);
    }
    if (mapping['confidence_policy'] !== TTP_ACCEPTANCE_POLICY_VERSION) {
      issues.push(`${stepId}: TTP decision uses an unknown confidence policy`);
    }
    if (
      mapping['accepted_precision_target'] !==
      TTP_ACCEPTED_PRECISION_TARGET
    ) {
      issues.push(`${stepId}: TTP decision has an unexpected precision target`);
    }
    if (mapping['abstained'] === true) {
      if (text(mapping['technique_id'])) {
        issues.push(`${stepId}: abstained TTP decision includes a technique`);
      }
      if (!text(mapping['abstention_reason'])) {
        issues.push(`${stepId}: abstained TTP decision is missing a reason`);
      }
    } else {
      if (!text(mapping['technique_id'])) {
        issues.push(`${stepId}: accepted TTP decision is missing a technique`);
      }
      if (
        confidence !== null &&
        confidence + Number.EPSILON < TTP_ACCEPTED_PRECISION_TARGET
      ) {
        issues.push(
          `${stepId}: accepted TTP confidence does not meet ${TTP_ACCEPTED_PRECISION_TARGET.toFixed(2)}`,
        );
      }
    }
  }

  for (const stepId of uniqueStepIds) {
    const count = decisionsByStep.get(stepId)?.length ?? 0;
    if (count === 0) {
      issues.push(`${stepId}: missing TTP decision`);
    } else if (count > 1) {
      issues.push(`${stepId}: duplicate TTP decisions (${count})`);
    }
  }
  return { issues, uniqueStepIds, decisionsByStep };
}

export function findTtpDecisionQualityIssues(
  attackTrees: readonly Json[],
  mappings: readonly Json[],
): string[] {
  return [...new Set(analyzeTtpDecisions(attackTrees, mappings).issues)];
}

export function evaluateDomainOutputQuality(
  input: DomainQualityInput,
): DomainQualityReport {
  const ttpAnalysis = analyzeTtpDecisions(
    input.attackTrees,
    input.ttpMappings,
  );
  const issues = [...ttpAnalysis.issues, ...findAttackTreeQualityIssues(input.attackTrees, input.threats)];
  const { uniqueStepIds, decisionsByStep } = ttpAnalysis;
  if ((input.threats?.length ?? 0) > 0 && input.attackTrees.length === 0) {
    issues.push('Threats exist but no attack trees were produced');
  }
  if ((input.threats?.length ?? 0) > 0 && uniqueStepIds.size === 0) {
    issues.push('Threats exist but no attack steps were produced');
  }

  issues.push(
    ...findMitigationQualityIssues(input.ttpMappings, input.mitigations, input),
  );

  const targets = acceptedTargets(input.ttpMappings);
  const allTargets = mitigationTargets(input.ttpMappings, input.attackTrees);
  const targetCoverage = allTargets.map((target) =>
    mitigationCoverageForTarget(target, input.mitigations, input.resolveEvidence),
  );
  const mitigatedTargets = targetCoverage.filter(({ covered }) => covered).length;
  const evidencedTargets = targetCoverage.filter(({ evidenced }) => evidenced).length;
  const acceptedConfidences = input.ttpMappings.flatMap((mapping) => {
    if (mapping['abstained'] === true) {
      return [];
    }
    const confidence = finiteProbability(mapping['calibrated_confidence']);
    return confidence === null ? [] : [confidence];
  });
  const abstentions = input.ttpMappings.filter(
    (mapping) => mapping['abstained'] === true,
  ).length;

  return {
    schemaVersion: '1.1.0',
    gatePassed: issues.length === 0,
    issues: [...new Set(issues)],
    counts: {
      threats: input.threats?.length ?? 0,
      attackSteps: uniqueStepIds.size,
      ttpDecisions: input.ttpMappings.length,
      acceptedTtpMappings: targets.length,
      ttpAbstentions: abstentions,
      mitigationTargets: allTargets.length,
      mitigatedTargets,
      evidencedTargets,
    },
    metrics: {
      ttpDecisionCoverage: ratio(
        [...uniqueStepIds].filter(
          (stepId) => (decisionsByStep.get(stepId)?.length ?? 0) === 1,
        ).length,
        uniqueStepIds.size,
        1,
      ),
      ttpAcceptedCoverage: ratio(targets.length, uniqueStepIds.size, 0),
      ttpAbstentionRate: ratio(abstentions, uniqueStepIds.size, 0),
      meanAcceptedConfidence:
        acceptedConfidences.length === 0
          ? null
          : acceptedConfidences.reduce((sum, value) => sum + value, 0) /
            acceptedConfidences.length,
      mitigationCoverage: allTargets.length === 0 ? null : mitigatedTargets / allTargets.length,
      mitigationEvidenceCoverage: allTargets.length === 0 ? null : evidencedTargets / allTargets.length,
    },
    policy: {
      ttpAcceptedPrecisionTarget: TTP_ACCEPTED_PRECISION_TARGET,
      ttpAcceptancePolicy: TTP_ACCEPTANCE_POLICY_VERSION,
    },
  };
}
