/**
 * Golden-parity test for the probability stage: the TS port must reproduce the
 * Python `compute_probabilities` output exactly (probability to 4dp, reach to
 * 4dp, and the rationale strings character-for-character).
 *
 * The fixture is generated from the real Python implementation
 * (see __fixtures__/probability_golden.json).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { computeProbabilities, indexByStep, type TreeLike } from './probability.js';

const here = dirname(fileURLToPath(import.meta.url));
const golden = JSON.parse(
  readFileSync(join(here, '__fixtures__/probability_golden.json'), 'utf8'),
) as {
  input: {
    trees: TreeLike[];
    ttp_by_step: Record<string, { similarity_score?: unknown }>;
    mitigations_by_step: Record<string, { priority?: unknown }>;
    tech_stack: string;
  };
  expected_trees: TreeLike[];
};

test('probability stage matches Python golden output exactly', () => {
  const trees = structuredClone(golden.input.trees);
  computeProbabilities(
    trees,
    golden.input.ttp_by_step,
    golden.input.mitigations_by_step,
    golden.input.tech_stack,
  );

  const expected = golden.expected_trees;
  assert.equal(trees.length, expected.length);

  for (let t = 0; t < trees.length; t++) {
    const got = trees[t]!.steps ?? [];
    const exp = expected[t]!.steps ?? [];
    assert.equal(got.length, exp.length, `step count for tree ${t}`);
    for (let i = 0; i < got.length; i++) {
      const g = got[i]!;
      const e = exp[i]!;
      assert.equal(g.id, e.id);
      // numeric fields: identical to 1e-9 (both rounded to 4dp upstream)
      assert.ok(
        Math.abs((g.probability ?? 0) - (e.probability ?? 0)) < 1e-9,
        `probability mismatch step ${g.id}: ${g.probability} != ${e.probability}`,
      );
      assert.ok(
        Math.abs((g.reach_probability ?? 0) - (e.reach_probability ?? 0)) < 1e-9,
        `reach mismatch step ${g.id}: ${g.reach_probability} != ${e.reach_probability}`,
      );
      // rationale strings: character-for-character
      assert.equal(
        g.probability_rationale,
        e.probability_rationale,
        `rationale mismatch step ${g.id}`,
      );
    }
  }
});

test('indexByStep indexes id and also_applies_to', () => {
  const idx = indexByStep(
    [{ attack_step_id: 's1', also_applies_to: ['s9'], priority: 2 }],
  );
  assert.equal(idx['s1']?.priority, 2);
  assert.equal(idx['s9']?.priority, 2, 'also_applies_to should alias to same entry');
});
