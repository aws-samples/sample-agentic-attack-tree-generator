import assert from 'node:assert/strict';
import test from 'node:test';
import { inferTtpEvaluation } from './infer-ttp.js';

const input = {
  labels: {
    schemaVersion: '1.0.0', datasetId: 'synthetic-contract-test', evaluationSplit: 'test',
    provenance: { heldOut: true, trainingRecordIds: [], trainingSourceIds: [], trainingAttackStepHashes: [] },
    records: [
      { id: 'a', sourceId: 'app-a', split: 'test', attackStep: 'Exploit the public service', acceptedTechniqueIds: ['T1190'] },
      { id: 'b', sourceId: 'app-b', split: 'test', attackStep: 'Deploy a documentation correction', acceptedTechniqueIds: [] },
    ],
  },
  review: { status: 'draft' }, model: 'test-model', frameworks: ['attack'],
};

test('inference evaluation sends only descriptions and records current predictions and no-match outcomes', async () => {
  const result = await inferTtpEvaluation(input, {
    async matchSteps(steps, options) {
      assert.deepEqual(steps, input.labels.records.map(record => record.attackStep));
      assert.equal(options?.embeddingsModel, 'test-model');
      return steps.map((attack_step, index) => ({
        attack_step,
        matches: index ? [] : [{
          technique_id: 'T1190', name: 'Exploit application', description: '',
          kill_chain_phases: [], similarity: .9, confidence: 'high', framework: 'attack',
        }],
      }));
    },
  });
  assert.equal(result.provenance.inference_performed, true);
  assert.equal(result.provenance.accuracy_acceptance_eligible, false);
  assert.equal(result.dataset.records[0]!.predictions[0]!.techniqueId, 'T1190');
  assert.equal(result.dataset.records[1]!.abstained, true);
  assert.equal(result.report.metrics.acceptedPrecision, 1);
});

test('saved predictions and missing inference results are rejected', async () => {
  const invalid = structuredClone(input);
  Object.assign(invalid.labels.records[0]!, { predictions: [] });
  await assert.rejects(inferTtpEvaluation(invalid), /labels only/);
  await assert.rejects(inferTtpEvaluation(input, { async matchSteps() { return []; } }), /omitted/);
});
