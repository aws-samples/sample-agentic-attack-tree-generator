/**
 * Pure-TS TTP-matching parity test. Verifies the in-process transformers.js
 * matcher returns the same top-1 MITRE techniques as the Python TTCMatcher on a
 * fixed step set (T1530 / T1548 / T1566 for the ATT&CK framework).
 *
 * Requires the converted ATTACK-BERT model + the STIX corpus + repo-root config,
 * so it is gated on `TF_ATTACK_BERT_DIR` (and skipped otherwise — the fast unit
 * suite stays model-free). Run it explicitly:
 *
 *   cd ts && TF_ATTACK_BERT_DIR=$PWD/models/attack-bert \
 *     TF_STIX_DIR=$PWD/../src/threatforest/data/threat-intelligence \
 *     node --import tsx/esm --test packages/engine/src/ml/matcher.test.ts
 *
 * Build the model first with `npm run convert-model`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chdir, cwd } from 'node:process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const MODEL_DIR = process.env.TF_ATTACK_BERT_DIR;
const hasModel = Boolean(MODEL_DIR && existsSync(join(MODEL_DIR, 'onnx', 'model.onnx')));

// The matcher's Config + STIX paths resolve relative to cwd = repo root.
const REPO_ROOT = process.env.TF_REPO_ROOT || join(cwd(), '..');

const EXPECTED_TOP1: Record<string, string> = {
  'exploit unvalidated key parameter to read arbitrary S3 object': 'T1530',
  'assume an over-permissive IAM role to escalate privileges': 'T1548',
  'send phishing email with malicious attachment for initial access': 'T1566',
};

test(
  'in-process TS matcher top-1 matches the Python TTCMatcher (ATT&CK)',
  { skip: hasModel ? false : 'set TF_ATTACK_BERT_DIR (run npm run convert-model) to enable' },
  async () => {
    const prev = cwd();
    if (existsSync(join(REPO_ROOT, '.threatforest', 'config.yaml'))) chdir(REPO_ROOT);
    try {
      const { matchStepsInProcess } = await import('./matcher.js');
      const steps = Object.keys(EXPECTED_TOP1);
      const results = await matchStepsInProcess(steps, { topK: 3, frameworks: ['attack'] });

      // Every step should match something (all three are real techniques).
      assert.equal(results.length, steps.length, 'all steps matched');
      for (const r of results) {
        const expected = EXPECTED_TOP1[r.attack_step];
        assert.ok(expected, `unexpected step ${r.attack_step}`);
        assert.equal(
          r.matches[0]?.technique_id,
          expected,
          `top-1 for "${r.attack_step.slice(0, 30)}" should be ${expected}`,
        );
      }
    } finally {
      chdir(prev);
    }
  },
);
