import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeProbabilities, indexByStep, updatePosterior, type TreeLike } from './probability.js';

test('a proposed mitigation cannot reduce current attack likelihood', () => {
  const baseline: TreeLike[] = [{ steps: [
    { id: 'root', category: 'fact', parent_id: '' },
    { id: 'step', parent_id: 'root', skill_required: 'med', access_required: 'authenticated', detectability: 'med', exploit_maturity: 'poc' },
  ] }];
  const recommendations = structuredClone(baseline);
  computeProbabilities(baseline, {}, {});
  computeProbabilities(recommendations, {}, { step: { priority: 1 } });
  assert.deepEqual(recommendations, baseline);
  assert.equal(baseline[0]!.steps![1]!.probability, 0.3775);
  assert.equal(baseline[0]!.steps![1]!.reach_probability, 0.3775);
  assert.deepEqual(updatePosterior(0.4, { mitigationPriority: 1 }), updatePosterior(0.4));
});

test('path reach remains multiplicative and fact nodes are preconditions', () => {
  const trees: TreeLike[] = [{ steps: [
    { id: 'root', category: 'fact', parent_id: '' },
    { id: 'first', parent_id: 'root' },
    { id: 'second', parent_id: 'first' },
  ] }];
  computeProbabilities(trees, {}, {});
  assert.equal(trees[0]!.steps![0]!.probability, 1);
  assert.equal(trees[0]!.steps![2]!.reach_probability, 0.1425);
});

test('indexByStep retains explicit control applicability', () => {
  const index = indexByStep([{ attack_step_id: 's1', also_applies_to: ['s9'], priority: 2 }]);
  assert.equal(index['s1'], index['s9']);
});
