import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { formatHumanReport, parseCliArguments, runCli } from './ttp-quality-cli.js';
import {
  evaluateTtpQuality,
  hashAttackStep,
  parseTtpEvaluationDataset,
  TtpEvaluationValidationError,
  type TtpEvaluationDataset,
} from './ttp-quality.js';

const fixturePath = fileURLToPath(
  new URL('./__fixtures__/ttp-quality-v1.json', import.meta.url),
);
const jsonlFixturePath = fileURLToPath(
  new URL('./__fixtures__/ttp-quality-v1.jsonl', import.meta.url),
);

async function loadFixture(): Promise<TtpEvaluationDataset> {
  return parseTtpEvaluationDataset(await readFile(fixturePath, 'utf8'), 'json', fixturePath);
}

function cloneDataset(dataset: TtpEvaluationDataset): TtpEvaluationDataset {
  return structuredClone(dataset);
}

function assertValidationIssue(action: () => unknown, pattern: RegExp): void {
  assert.throws(action, (error: unknown) => {
    assert.ok(error instanceof TtpEvaluationValidationError);
    assert.match(error.message, pattern);
    return true;
  });
}

test('evaluates accepted precision, coverage, abstention, recall, and calibration separately', async () => {
  const dataset = await loadFixture();
  const report = evaluateTtpQuality(dataset);

  assert.deepEqual(report.counts, {
    records: 10,
    answered: 8,
    abstained: 2,
    acceptedTop1: 6,
    acceptedLabels: 10,
    recalledLabelsAtK: 8,
  });
  assert.equal(report.metrics.acceptedPrecision, 0.75);
  assert.equal(report.metrics.coverage, 0.8);
  assert.equal(report.metrics.abstentionRate, 0.2);
  assert.equal(report.metrics.topKRecall, 0.8);
  assert.ok(
    Math.abs((report.metrics.expectedCalibrationError ?? Number.NaN) - 0.07) < 1e-12,
  );
  assert.equal(report.gate.passed, true);
});

test('the precision gate is configurable and does not impose a coverage gate', async () => {
  const dataset = await loadFixture();
  const strict = evaluateTtpQuality(dataset, { acceptedPrecisionThreshold: 0.8 });
  const permissive = evaluateTtpQuality(dataset, { acceptedPrecisionThreshold: 0.7 });

  assert.equal(strict.gate.passed, false);
  assert.match(strict.gate.reason, /0\.7500 < 0\.8000/);
  assert.equal(permissive.gate.passed, true);
  assert.equal(permissive.metrics.coverage, strict.metrics.coverage);
});

test('parses a versioned JSONL dataset and preserves explicit abstentions', async () => {
  const dataset = parseTtpEvaluationDataset(
    await readFile(jsonlFixturePath, 'utf8'),
    'jsonl',
    jsonlFixturePath,
  );
  const report = evaluateTtpQuality(dataset);

  assert.equal(dataset.schemaVersion, '1.0.0');
  assert.equal(dataset.records[1]?.abstentionReason?.includes('relevance threshold'), true);
  assert.equal(report.metrics.acceptedPrecision, 1);
  assert.equal(report.metrics.coverage, 0.5);
  assert.equal(report.metrics.topKRecall, 0.5);
});

test('rejects duplicate IDs, duplicate labels, malformed labels, and invalid ranks', async () => {
  const dataset = cloneDataset(await loadFixture());
  dataset.records[1]!.id = dataset.records[0]!.id;
  dataset.records[1]!.acceptedTechniqueIds = ['T1530', 'T1530'];
  dataset.records[1]!.predictions[0]!.techniqueId = 'not a canonical label!';
  dataset.records[1]!.predictions[1]!.rank = 4;

  assertValidationIssue(
    () => parseTtpEvaluationDataset(JSON.stringify(dataset), 'json'),
    /canonical ATT&CK/,
  );

  dataset.records[1]!.predictions[0]!.techniqueId = 'T1530';
  assertValidationIssue(
    () => parseTtpEvaluationDataset(JSON.stringify(dataset), 'json'),
    /duplicate record ID "eval-api-001"/,
  );
  assertValidationIssue(
    () => parseTtpEvaluationDataset(JSON.stringify(dataset), 'json'),
    /duplicate ID "T1530"/,
  );
  assertValidationIssue(
    () => parseTtpEvaluationDataset(JSON.stringify(dataset), 'json'),
    /expected 2, got 4/,
  );
});

test('rejects duplicate normalized text and declared record, source, or text leakage', async () => {
  const dataset = cloneDataset(await loadFixture());
  const leaked = dataset.records[0]!;
  dataset.provenance.trainingRecordIds.push(leaked.id);
  dataset.provenance.trainingSourceIds.push(leaked.sourceId);
  dataset.provenance.trainingAttackStepHashes.push(hashAttackStep(leaked.attackStep));
  dataset.records[1]!.attackStep = `  ${leaked.attackStep.toLocaleUpperCase('en-US')}  `;

  const text = JSON.stringify(dataset);
  assertValidationIssue(() => parseTtpEvaluationDataset(text, 'json'), /leaks from declared training data/);
  assertValidationIssue(() => parseTtpEvaluationDataset(text, 'json'), /text leaks from declared training data/);
  assertValidationIssue(() => parseTtpEvaluationDataset(text, 'json'), /duplicates normalized attack step/);
});

test('rejects inconsistent abstention states and all-abstention runs cannot pass', async () => {
  const malformed = cloneDataset(await loadFixture());
  malformed.records[8]!.abstentionReason = undefined;
  malformed.records[8]!.predictions.push({
    rank: 1,
    techniqueId: 'T1565',
    modelConfidence: 0.5,
    similarity: 0.5,
  });
  assertValidationIssue(
    () => parseTtpEvaluationDataset(JSON.stringify(malformed), 'json'),
    /must be empty when abstained is true/,
  );
  assertValidationIssue(
    () => parseTtpEvaluationDataset(JSON.stringify(malformed), 'json'),
    /is required when abstained is true/,
  );

  const allAbstained = cloneDataset(await loadFixture());
  for (const record of allAbstained.records) {
    record.abstained = true;
    record.abstentionReason = 'No candidate met the acceptance threshold.';
    record.predictions = [];
  }
  const report = evaluateTtpQuality(allAbstained);
  assert.equal(report.metrics.acceptedPrecision, null);
  assert.equal(report.metrics.expectedCalibrationError, null);
  assert.equal(report.metrics.coverage, 0);
  assert.equal(report.metrics.abstentionRate, 1);
  assert.equal(report.gate.passed, false);
});

test('CLI parsing, human output, and exit status are deterministic', async () => {
  const parsed = parseCliArguments([
    '--dataset',
    fixturePath,
    '--precision-threshold',
    '0.8',
    '--top-k',
    '2',
    '--calibration-bins',
    '5',
    '--json',
  ]);
  assert.deepEqual(parsed, {
    datasetPath: fixturePath,
    acceptedPrecisionThreshold: 0.8,
    topK: 2,
    calibrationBins: 5,
    json: true,
  });

  const report = evaluateTtpQuality(await loadFixture());
  assert.equal(formatHumanReport(report).includes('Accepted precision: 0.7500'), true);

  let stdout = '';
  let stderr = '';
  const status = await runCli(
    ['--dataset', fixturePath, '--precision-threshold', '0.8', '--json'],
    {
      write: (chunk) => {
        stdout += String(chunk);
        return true;
      },
    },
    {
      write: (chunk) => {
        stderr += String(chunk);
        return true;
      },
    },
  );
  assert.equal(status, 1);
  assert.equal(stderr, '');
  assert.equal((JSON.parse(stdout) as { gate: { passed: boolean } }).gate.passed, false);
});
