import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

import { verifyMitigationOutput } from '../agents/mitigation.js';
import {
  collectThreatResults,
  ParallelThreatProcessingError,
} from '../stages/parallel.js';
import { verifyTtpCoverage } from '../stages/ttp.js';
import { evaluateDomainOutputQuality } from './domain-quality.js';
import { createSourceEvidenceResolver, type EvidenceResolver } from './evidence.js';
import {
  selectTtpDecision,
  TTP_ACCEPTANCE_POLICY_VERSION,
} from './ttp-confidence.js';

const trees = [
  {
    id: 'AT001',
    threat_id: 'THR-1',
    steps: [
      { id: 'AT001-S1', description: 'Read a private object', parent_id: '' },
      { id: 'AT001-S2', description: 'Exfiltrate the object', parent_id: 'AT001-S1' },
    ],
  },
];

function accepted(stepId: string, techniqueId: string, confidence = 0.82) {
  return {
    attack_step_id: stepId,
    technique_id: techniqueId,
    technique_name: 'Technique',
    similarity_score: confidence,
    calibrated_confidence: confidence,
    confidence_policy: TTP_ACCEPTANCE_POLICY_VERSION,
    accepted_precision_target: 0.7,
    acceptance_margin: 0.12,
    framework: 'attack',
    abstained: false,
  };
}

function abstained(stepId: string) {
  return {
    attack_step_id: stepId,
    attack_step_description: 'Uncertain behavior',
    calibrated_confidence: 0.62,
    confidence_policy: TTP_ACCEPTANCE_POLICY_VERSION,
    accepted_precision_target: 0.7,
    acceptance_margin: 0.01,
    abstained: true,
    abstention_reason: 'Candidate confidence is below the acceptance target.',
  };
}

function mitigation(stepId = 'AT001-S1') {
  return {
    attack_step_id: stepId,
    technique_id: 'T1530',
    mitigation_text: 'Restrict object access to the workload role.',
    implementation_guidance: 'Apply a bucket policy and verify with access analysis.',
    remediation_type: 'quick_win',
    priority: 1,
    evidence: [
      {
        source_type: 'repository',
        source_ref: 'infra/storage.ts',
        excerpt: 'The bucket grants read access to the workload role.',
        relevance: 'This is the authorization boundary for the mapped step.',
      },
    ],
    also_applies_to: [],
  };
}

const verifiedEvidence: EvidenceResolver = (entry) =>
  entry['source_ref'] === 'infra/storage.ts' &&
  entry['excerpt'] === 'The bucket grants read access to the workload role.'
    ? { source_ref: 'infra/storage.ts', source_sha256: 'a'.repeat(64), line_start: 1, line_end: 1 }
    : null;

test('TTP acceptance separates candidate retrieval from calibrated report promotion', () => {
  const acceptedDecision = selectTtpDecision({
    attack_step_id: 'AT001-S1',
    attack_step_description: 'Read a private object',
    top_k: [
      {
        technique_id: 'T1530',
        technique_name: 'Data from Cloud Storage',
        similarity_score: 0.81,
        framework: 'attack',
      },
      {
        technique_id: 'T1213',
        technique_name: 'Data from Information Repositories',
        similarity_score: 0.68,
        framework: 'attack',
      },
    ],
  });
  assert.equal(acceptedDecision.abstained, false);
  assert.equal(
    acceptedDecision.calibrated_confidence >=
      acceptedDecision.accepted_precision_target,
    true,
  );

  const ambiguous = selectTtpDecision({
    attack_step_id: 'AT001-S2',
    top_k: [
      { technique_id: 'T1041', similarity_score: 0.76 },
      { technique_id: 'T1567', similarity_score: 0.74 },
    ],
  });
  assert.equal(ambiguous.abstained, true);
  assert.match(ambiguous.abstention_reason, /ambiguous/);

  const belowTarget = selectTtpDecision({
    attack_step_id: 'AT001-S2',
    top_k: [{ technique_id: 'T1041', similarity_score: 0.69 }],
  });
  assert.equal(belowTarget.abstained, true);
  assert.match(belowTarget.abstention_reason, /below/);
});

test('irrelevant cloud techniques are excluded before selecting the next candidate', () => {
  const decision = selectTtpDecision(
    {
      attack_step_id: 'AT001-S1',
      top_k: [
        { technique_id: 'T1014', similarity_score: 0.95 },
        { technique_id: 'T1530', similarity_score: 0.8 },
      ],
    },
    new Set(['T1014']),
  );
  assert.equal(decision.abstained, false);
  if (decision.abstained) assert.fail('expected an accepted decision');
  assert.equal(decision.technique_id, 'T1530');
});

test('domain metrics distinguish accepted coverage, abstention, and evidenced mitigation', () => {
  const report = evaluateDomainOutputQuality({
    threats: [{ id: 'THR-1' }],
    attackTrees: trees,
    ttpMappings: [accepted('AT001-S1', 'T1530'), abstained('AT001-S2')],
    mitigations: [mitigation()],
    resolveEvidence: verifiedEvidence,
  });
  assert.equal(report.gatePassed, false);
  assert.match(report.issues.join('; '), /AT001-S2: no mitigation/);
  assert.deepEqual(report.counts, {
    threats: 1,
    attackSteps: 2,
    ttpDecisions: 2,
    acceptedTtpMappings: 1,
    ttpAbstentions: 1,
    mitigationTargets: 2,
    mitigatedTargets: 1,
    evidencedTargets: 1,
  });
  assert.equal(report.metrics.ttpDecisionCoverage, 1);
  assert.equal(report.metrics.ttpAcceptedCoverage, 0.5);
  assert.equal(report.metrics.ttpAbstentionRate, 0.5);
  assert.equal(report.metrics.mitigationCoverage, 0.5);
  assert.equal(report.metrics.mitigationEvidenceCoverage, 0.5);
});

test('all-abstained steps still require evidenced mitigations; empty coverage is not 100%', () => {
  const input = {
    threats: [{ id: 'THR-1' }], attackTrees: trees,
    ttpMappings: [abstained('AT001-S1'), abstained('AT001-S2')],
    mitigations: [] as Record<string, unknown>[],
    resolveEvidence: verifiedEvidence,
  };
  const missing = evaluateDomainOutputQuality(input);
  assert.equal(missing.gatePassed, false);
  assert.equal(missing.metrics.mitigationCoverage, 0);
  assert.equal(missing.counts.mitigationTargets, 2);
  const covered = evaluateDomainOutputQuality({
    ...input, mitigations: [
      { ...mitigation(), technique_id: '', also_applies_to: ['AT001-S2'] },
    ],
  });
  assert.equal(covered.gatePassed, true);
  assert.equal(covered.metrics.ttpAcceptedCoverage, 0);
  assert.equal(covered.metrics.mitigationCoverage, 1);
  assert.equal(evaluateDomainOutputQuality({
    attackTrees: [], ttpMappings: [], mitigations: [],
  }).metrics.mitigationCoverage, null);
});

test('domain gate rejects invented evidence, missing threat trees, cycles, and cross-tree parents', () => {
  const report = evaluateDomainOutputQuality({
    threats: [{ id: 'THR-1' }, { id: 'THR-2' }],
    attackTrees: [{ ...trees[0], steps: [
      { id: 'AT001-S1', parent_id: 'AT001-S1' },
      { id: 'AT001-S2', parent_id: 'AT999-S1' },
    ] }],
    ttpMappings: [accepted('AT001-S1', 'T1530'), abstained('AT001-S2')],
    mitigations: [{ ...mitigation(), evidence: [{
      source_type: 'repository', source_ref: 'invented.ts', excerpt: 'fake', relevance: 'fake',
    }] }],
    resolveEvidence: verifiedEvidence,
  });
  assert.equal(report.gatePassed, false);
  assert.match(report.issues.join('; '), /THR-2: threat has no attack tree/);
  assert.match(report.issues.join('; '), /cycle/);
  assert.match(report.issues.join('; '), /outside its attack tree/);
  assert.match(report.issues.join('; '), /unverifiable evidence/);
  assert.equal(report.metrics.mitigationEvidenceCoverage, 0);
});

test('quality gate rejects duplicate decisions, low-confidence promotion, and missing evidence', () => {
  const first = accepted('AT001-S1', 'T1530', 0.69);
  const report = evaluateDomainOutputQuality({
    attackTrees: trees,
    ttpMappings: [first, accepted('AT001-S1', 'T1213'), abstained('AT001-S2')],
    mitigations: [{ ...mitigation(), evidence: [] }],
  });
  assert.equal(report.gatePassed, false);
  assert.match(report.issues.join('; '), /duplicate TTP decisions/);
  assert.match(report.issues.join('; '), /does not meet 0\.70/);
  assert.match(report.issues.join('; '), /no usable evidence/);

  const disappeared = evaluateDomainOutputQuality({
    threats: [{ id: 'THR-1' }],
    attackTrees: [],
    ttpMappings: [],
    mitigations: [],
  });
  assert.equal(disappeared.gatePassed, false);
  assert.match(disappeared.issues.join('; '), /no attack trees/);
});

test('filesystem verifiers reject duplicate mappings and fail closed on mitigation gaps', async () => {
  await withState(async (root, runDir) => {
    const state = join(runDir, 'state');
    await writeJson(join(state, 'attack_trees.json'), { attack_trees: trees });
    await writeJson(join(state, 'ttp_mappings.json'), {
      ttp_mappings: [
        accepted('AT001-S1', 'T1530'),
        accepted('AT001-S1', 'T1213'),
        abstained('AT001-S2'),
      ],
    });
    await writeJson(join(state, 'mitigations.json'), {
      mitigations: [{ ...mitigation(), evidence: [] }],
    });

    const coverage = verifyTtpCoverage(root, runDir);
    assert.equal(coverage[0], false);
    assert.match(coverage[1], /duplicate TTP decisions/);

    await writeJson(join(state, 'ttp_mappings.json'), {
      ttp_mappings: [accepted('AT001-S1', 'T1530'), abstained('AT001-S2')],
    });
    const invalidMitigations = verifyMitigationOutput(root, runDir);
    assert.equal(invalidMitigations[0], false);
    assert.match(invalidMitigations[1], /no usable evidence/);

    await mkdir(join(root, 'infra'));
    await writeFile(join(root, 'infra/storage.ts'), 'The bucket grants read access to the workload role.\n');
    await writeJson(join(state, 'mitigations.json'), { mitigations: [
      mitigation(), { ...mitigation('AT001-S2'), technique_id: '' },
    ] });
    assert.deepEqual(verifyTtpCoverage(root, runDir), [
      true,
      'Every attack step has exactly one accepted or abstained TTP decision',
    ]);
    assert.equal(verifyMitigationOutput(root, runDir)[0], true);
    assert.ok(createSourceEvidenceResolver(root)(mitigation().evidence[0]!));
  });
});

test('per-threat work retries only failures and cannot return a partial result set', async () => {
  const attempts = [0, 0, 0];
  const values = await collectThreatResults(3, 1, async (index) => {
    attempts[index] = (attempts[index] ?? 0) + 1;
    if (index === 1 && attempts[index] === 1) {
      throw new Error('transient failure');
    }
    return `result-${index}`;
  });
  assert.deepEqual(values, ['result-0', 'result-1', 'result-2']);
  assert.deepEqual(attempts, [1, 2, 1]);

  await assert.rejects(
    collectThreatResults(2, 2, async (index) => {
      if (index === 1) throw new Error('persistent failure');
      return index;
    }),
    (error: unknown) => {
      assert.ok(error instanceof ParallelThreatProcessingError);
      assert.deepEqual(error.failedThreatIndexes, [1]);
      return true;
    },
  );
});

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, JSON.stringify(value), 'utf8');
}

async function withState(
  run: (repoPath: string, runDir: string) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp('/tmp/threatforest-output-quality-');
  const repoPath = join(root, 'source');
  const runDir = join(root, 'run');
  try {
    await mkdir(repoPath);
    await mkdir(join(runDir, 'state'), { recursive: true });
    await run(repoPath, runDir);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
