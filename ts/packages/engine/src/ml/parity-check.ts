/**
 * Standalone TS-vs-Python TTP parity check (not a unit test — needs the model +
 * STIX corpus + the repo-root .threatforest/config.yaml). Run from ts/:
 *
 *   TF_ATTACK_BERT_DIR=$PWD/models/attack-bert \
 *   TF_STIX_DIR=<repo>/src/threatforest/data/threat-intelligence \
 *   node --import tsx/esm packages/engine/src/ml/parity-check.ts <repoRoot>
 *
 * It chdir's to the repo root so Config resolves, runs the in-process matcher,
 * and prints top-1 technique ids to compare against the Python TTCMatcher.
 */
import { chdir } from 'node:process';
import { matchStepsInProcess } from './matcher.js';

const repoRoot = process.argv[2];
if (repoRoot) chdir(repoRoot);

const STEPS = [
  'exploit unvalidated key parameter to read arbitrary S3 object',
  'assume an over-permissive IAM role to escalate privileges',
  'send phishing email with malicious attachment for initial access',
];

const t0 = Date.now();
const results = await matchStepsInProcess(STEPS, { topK: 3, frameworks: ['attack'] });
// eslint-disable-next-line no-console
console.error(`[parity] matched ${results.length} steps in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

const top1: Record<string, string> = {};
for (const m of results) top1[m.attack_step.slice(0, 30)] = m.matches[0]?.technique_id ?? '(none)';
// eslint-disable-next-line no-console
console.log(JSON.stringify(top1));
