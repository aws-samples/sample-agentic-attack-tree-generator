import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalThreatStatement, normalizeAttackTrees, normalizeThreats, renumberAttackTrees } from './output-contract.js';

const statement = 'A malicious user with an account can alter payment instructions, which leads to fraudulent transfers, resulting in reduced integrity of payments.';
const draft = { title: 'Payment tampering', description: statement, priority: 'high', affected_components: ['Payments API'] };

test('provider-specific threat IDs normalize to identical metadata and syntax', () => {
  const outputs = ['64c04a33-2103-4a94-a61b-745ab6368853', 'TS099', 'threat-1', '1'].map(id =>
    normalizeThreats([{ ...draft, id }], 'generated'),
  );
  for (const output of outputs) assert.deepEqual(output, outputs[0]);
  assert.equal(outputs[0]![0]!.id, 'TS001');
  assert.equal(outputs[0]![0]!.description, statement);
  assert.throws(() => canonicalThreatStatement('Payments might be insecure'), /Threat description must use/);
});

test('review preserves existing IDs and original source IDs remain separate', () => {
  const previous = normalizeThreats([{ ...draft, id: 'external-7' }, { ...draft, title: 'Other' }], 'user_provided');
  const revised = normalizeThreats([{ ...draft, id: 'TS002' }, { ...draft, title: 'New' }], 'user_provided', previous);
  assert.deepEqual(revised.map(threat => threat.id), ['TS002', 'TS003']);
  assert.equal(previous[0]!.source_id, 'external-7');
});

function tree() {
  return {
    id: 'random-tree', threat_id: 'TS001', root_goal: 'Alter payment',
    steps: [
      { id: 'random-root', title: 'Account', description: 'A malicious user with an account', category: 'fact', parent_id: '' },
      { id: 'random-child', title: 'Alter instructions', description: 'Modify the beneficiary', parent_id: 'random-root', skill_required: 'low', access_required: 'authenticated', detectability: 'med', exploit_maturity: 'poc' },
    ],
  };
}

test('tree storage assigns all IDs, remaps parents, and derives leaf flags independently of a provider', () => {
  const threats = normalizeThreats([draft], 'generated');
  const trees = normalizeAttackTrees([tree()], threats);
  assert.deepEqual(normalizeAttackTrees(trees, threats), trees, 'canonical storage must round-trip');
  const steps = trees[0]!['steps'] as Record<string, unknown>[];
  assert.equal(trees[0]!['id'], 'AT001');
  assert.equal(steps[0]!['title'], 'Attacker prerequisites');
  assert.equal(steps[0]!['description'], 'A malicious user with an account.');
  assert.deepEqual(steps.map(step => [step['id'], step['parent_id'], step['is_leaf']]), [
    ['AT001-S1', '', false], ['AT001-S2', 'AT001-S1', true],
  ]);
  const [merged, mapping] = renumberAttackTrees(trees, 3);
  assert.equal(mapping['AT001-S2'], 'AT003-S2');
  assert.equal((merged[0]!['steps'] as Record<string, unknown>[])[1]!['parent_id'], 'AT003-S1');
});

test('generated fact roots use canonical prerequisites regardless of model wording', () => {
  const first = tree();
  first.steps[0]!.description = 'A generated threat source with a malicious user';
  const second = tree();
  second.steps[0]!.description = 'The attack has already succeeded';
  const threats = normalizeThreats([draft], 'generated');
  assert.deepEqual(normalizeAttackTrees([first], threats), normalizeAttackTrees([second], threats));
});

test('retries retain IDs and removed high IDs are not recycled', () => {
  const previous = normalizeThreats([{ ...draft, id: 'random-a' }], 'generated');
  assert.equal(normalizeThreats([{ ...draft, id: 'random-b' }], 'generated', previous)[0]!.id, 'TS001');
  assert.equal(normalizeThreats([{ ...draft, title: 'New' }], 'generated', previous, 7)[0]!.id, 'TS007');
});

test('invalid ownership, malformed factors, duplicate steps and broken parents are rejected', () => {
  const threats = normalizeThreats([draft], 'generated');
  assert.throws(() => normalizeAttackTrees([{ ...tree(), threat_id: 'unknown' }], threats), /Unknown threat/);
  const broken = tree();
  broken.steps[1]!.parent_id = 'missing';
  assert.throws(() => normalizeAttackTrees([broken], threats), /unknown parent/);
  const duplicate = tree();
  duplicate.steps[1]!.id = 'random-root';
  assert.throws(() => normalizeAttackTrees([duplicate], threats), /duplicate IDs/);
});
