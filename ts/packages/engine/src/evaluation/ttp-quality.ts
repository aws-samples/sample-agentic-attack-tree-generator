import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { z } from 'zod';

export const TTP_EVALUATION_SCHEMA_VERSION = '1.0.0' as const;
export const DEFAULT_ACCEPTED_PRECISION_THRESHOLD = 0.7;
export const DEFAULT_TOP_K = 3;
export const DEFAULT_CALIBRATION_BINS = 10;

const techniqueIdPattern =
  /^(?:T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?|[a-z][a-z0-9]*(?:-[a-z0-9]+)*)$/;
const sha256Pattern = /^[a-f0-9]{64}$/;

const identifier = z.string().trim().min(1).max(256);
const probability = z.number().finite().min(0).max(1);
const techniqueId = z
  .string()
  .trim()
  .regex(
    techniqueIdPattern,
    'must be a canonical ATT&CK (T1234[.001]), ATLAS (AML.T1234[.001]), or Wiz slug ID',
  );

const provenanceSchema = z
  .object({
    heldOut: z.literal(true),
    trainingRecordIds: z.array(identifier),
    trainingSourceIds: z.array(identifier),
    trainingAttackStepHashes: z.array(
      z.string().regex(sha256Pattern, 'must be a lowercase SHA-256 hex digest'),
    ),
  })
  .strict();

const predictionSchema = z
  .object({
    rank: z.number().int().positive(),
    techniqueId,
    modelConfidence: probability,
    similarity: probability,
  })
  .strict();

const recordSchema = z
  .object({
    id: identifier,
    sourceId: identifier,
    split: z.literal('test'),
    attackStep: z.string().trim().min(1).max(20_000),
    acceptedTechniqueIds: z.array(techniqueId),
    abstained: z.boolean(),
    abstentionReason: z.string().trim().min(1).max(2_000).optional(),
    predictions: z.array(predictionSchema),
  })
  .strict();

const metadataFields = {
  schemaVersion: z.literal(TTP_EVALUATION_SCHEMA_VERSION),
  datasetId: identifier,
  evaluationSplit: z.literal('test'),
  provenance: provenanceSchema,
};

const jsonDatasetSchema = z
  .object({
    ...metadataFields,
    records: z.array(recordSchema).min(1),
  })
  .strict();

const jsonlMetadataSchema = z
  .object({
    type: z.literal('metadata'),
    ...metadataFields,
  })
  .strict();

const jsonlRecordSchema = z
  .object({
    type: z.literal('record'),
    ...recordSchema.shape,
  })
  .strict();

export interface TtpPrediction {
  rank: number;
  techniqueId: string;
  modelConfidence: number;
  similarity: number;
}

export interface TtpEvaluationRecord {
  id: string;
  sourceId: string;
  split: 'test';
  attackStep: string;
  acceptedTechniqueIds: string[];
  abstained: boolean;
  abstentionReason?: string;
  predictions: TtpPrediction[];
}

export interface TtpEvaluationDataset {
  schemaVersion: typeof TTP_EVALUATION_SCHEMA_VERSION;
  datasetId: string;
  evaluationSplit: 'test';
  provenance: {
    heldOut: true;
    trainingRecordIds: string[];
    trainingSourceIds: string[];
    trainingAttackStepHashes: string[];
  };
  records: TtpEvaluationRecord[];
}

export interface TtpQualityOptions {
  acceptedPrecisionThreshold?: number;
  topK?: number;
  calibrationBins?: number;
}

export interface TtpQualityReport {
  schemaVersion: typeof TTP_EVALUATION_SCHEMA_VERSION;
  datasetId: string;
  configuration: {
    acceptedPrecisionThreshold: number;
    topK: number;
    calibrationBins: number;
  };
  counts: {
    records: number;
    answered: number;
    abstained: number;
    acceptedTop1: number;
    acceptedLabels: number;
    recalledLabelsAtK: number;
  };
  metrics: {
    acceptedPrecision: number | null;
    coverage: number;
    abstentionRate: number;
    topKRecall: number;
    expectedCalibrationError: number | null;
  };
  gate: {
    metric: 'acceptedPrecision';
    threshold: number;
    passed: boolean;
    reason: string;
  };
}

export class TtpEvaluationValidationError extends Error {
  constructor(readonly issues: string[]) {
    super(`Invalid TTP evaluation dataset:\n- ${issues.join('\n- ')}`);
    this.name = 'TtpEvaluationValidationError';
  }
}

function formatZodIssues(error: z.ZodError, prefix = ''): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.length === 0 ? prefix || 'dataset' : [prefix, ...issue.path].filter(Boolean).join('.');
    return `${path}: ${issue.message}`;
  });
}

function parseJson(text: string, sourceName: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new TtpEvaluationValidationError([`${sourceName}: invalid JSON: ${message}`]);
  }
}

function parseJsonl(text: string, sourceName: string): TtpEvaluationDataset {
  const lines = text.split(/\r?\n/u);
  const entries: Array<{ line: number; value: unknown }> = [];
  const issues: string[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const value = lines[index]?.trim() ?? '';
    if (value === '' || value.startsWith('#')) {
      continue;
    }
    try {
      entries.push({ line: index + 1, value: JSON.parse(value) as unknown });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      issues.push(`${sourceName}:${index + 1}: invalid JSON: ${message}`);
    }
  }

  if (issues.length > 0) {
    throw new TtpEvaluationValidationError(issues);
  }
  const first = entries[0];
  if (first === undefined) {
    throw new TtpEvaluationValidationError([`${sourceName}: JSONL dataset is empty`]);
  }

  const metadata = jsonlMetadataSchema.safeParse(first.value);
  if (!metadata.success) {
    throw new TtpEvaluationValidationError(
      formatZodIssues(metadata.error, `${sourceName}:${first.line}`),
    );
  }

  const records: TtpEvaluationRecord[] = [];
  for (const entry of entries.slice(1)) {
    const parsed = jsonlRecordSchema.safeParse(entry.value);
    if (!parsed.success) {
      issues.push(...formatZodIssues(parsed.error, `${sourceName}:${entry.line}`));
      continue;
    }
    const { type: _type, ...record } = parsed.data;
    records.push(record);
  }
  if (records.length === 0) {
    issues.push(`${sourceName}: JSONL dataset must contain at least one record`);
  }
  if (issues.length > 0) {
    throw new TtpEvaluationValidationError(issues);
  }

  const { type: _type, ...fields } = metadata.data;
  return validateDataset({ ...fields, records });
}

function assertNoDuplicates(values: string[], path: string, issues: string[]): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      issues.push(`${path}: duplicate ID "${value}"`);
    }
    seen.add(value);
  }
}

function normalizeAttackStep(value: string): string {
  return value.trim().replace(/\s+/gu, ' ').toLocaleLowerCase('en-US');
}

export function hashAttackStep(value: string): string {
  return createHash('sha256').update(normalizeAttackStep(value), 'utf8').digest('hex');
}

function validateDataset(value: unknown): TtpEvaluationDataset {
  const parsed = jsonDatasetSchema.safeParse(value);
  if (!parsed.success) {
    throw new TtpEvaluationValidationError(formatZodIssues(parsed.error));
  }

  const dataset = parsed.data;
  const issues: string[] = [];
  assertNoDuplicates(dataset.provenance.trainingRecordIds, 'provenance.trainingRecordIds', issues);
  assertNoDuplicates(dataset.provenance.trainingSourceIds, 'provenance.trainingSourceIds', issues);
  assertNoDuplicates(
    dataset.provenance.trainingAttackStepHashes,
    'provenance.trainingAttackStepHashes',
    issues,
  );

  const trainingRecordIds = new Set(dataset.provenance.trainingRecordIds);
  const trainingSourceIds = new Set(dataset.provenance.trainingSourceIds);
  const trainingHashes = new Set(dataset.provenance.trainingAttackStepHashes);
  const recordIds = new Set<string>();
  const normalizedSteps = new Map<string, string>();

  for (const [index, record] of dataset.records.entries()) {
    const path = `records.${index}`;
    if (recordIds.has(record.id)) {
      issues.push(`${path}.id: duplicate record ID "${record.id}"`);
    }
    recordIds.add(record.id);

    if (trainingRecordIds.has(record.id)) {
      issues.push(`${path}.id: record ID "${record.id}" leaks from declared training data`);
    }
    if (trainingSourceIds.has(record.sourceId)) {
      issues.push(`${path}.sourceId: source "${record.sourceId}" leaks from declared training data`);
    }

    const normalizedStep = normalizeAttackStep(record.attackStep);
    const duplicateRecordId = normalizedSteps.get(normalizedStep);
    if (duplicateRecordId !== undefined) {
      issues.push(
        `${path}.attackStep: duplicates normalized attack step from record "${duplicateRecordId}"`,
      );
    } else {
      normalizedSteps.set(normalizedStep, record.id);
    }

    const attackStepHash = hashAttackStep(record.attackStep);
    if (trainingHashes.has(attackStepHash)) {
      issues.push(`${path}.attackStep: text leaks from declared training data (${attackStepHash})`);
    }

    assertNoDuplicates(record.acceptedTechniqueIds, `${path}.acceptedTechniqueIds`, issues);
    assertNoDuplicates(
      record.predictions.map((prediction) => prediction.techniqueId),
      `${path}.predictions`,
      issues,
    );

    for (const [predictionIndex, prediction] of record.predictions.entries()) {
      const expectedRank = predictionIndex + 1;
      if (prediction.rank !== expectedRank) {
        issues.push(
          `${path}.predictions.${predictionIndex}.rank: expected ${expectedRank}, got ${prediction.rank}`,
        );
      }
    }

    if (record.abstained) {
      if (record.predictions.length > 0) {
        issues.push(`${path}.predictions: must be empty when abstained is true`);
      }
      if (record.abstentionReason === undefined) {
        issues.push(`${path}.abstentionReason: is required when abstained is true`);
      }
    } else {
      if (record.predictions.length === 0) {
        issues.push(`${path}.predictions: must not be empty when abstained is false`);
      }
      if (record.abstentionReason !== undefined) {
        issues.push(`${path}.abstentionReason: must be omitted when abstained is false`);
      }
    }
  }

  if (issues.length > 0) {
    throw new TtpEvaluationValidationError(issues);
  }
  return dataset;
}

export function parseTtpEvaluationDataset(
  text: string,
  format: 'json' | 'jsonl',
  sourceName = '<dataset>',
): TtpEvaluationDataset {
  if (format === 'jsonl') {
    return parseJsonl(text, sourceName);
  }
  return validateDataset(parseJson(text, sourceName));
}

export async function loadTtpEvaluationDataset(path: string): Promise<TtpEvaluationDataset> {
  const text = await readFile(path, 'utf8');
  const format = path.toLocaleLowerCase('en-US').endsWith('.jsonl') ? 'jsonl' : 'json';
  return parseTtpEvaluationDataset(text, format, path);
}

function validateOptions(options: TtpQualityOptions): Required<TtpQualityOptions> {
  const acceptedPrecisionThreshold =
    options.acceptedPrecisionThreshold ?? DEFAULT_ACCEPTED_PRECISION_THRESHOLD;
  const topK = options.topK ?? DEFAULT_TOP_K;
  const calibrationBins = options.calibrationBins ?? DEFAULT_CALIBRATION_BINS;
  const issues: string[] = [];

  if (
    !Number.isFinite(acceptedPrecisionThreshold) ||
    acceptedPrecisionThreshold < 0 ||
    acceptedPrecisionThreshold > 1
  ) {
    issues.push('acceptedPrecisionThreshold must be between 0 and 1');
  }
  if (!Number.isInteger(topK) || topK < 1) {
    issues.push('topK must be a positive integer');
  }
  if (!Number.isInteger(calibrationBins) || calibrationBins < 1 || calibrationBins > 100) {
    issues.push('calibrationBins must be an integer between 1 and 100');
  }
  if (issues.length > 0) {
    throw new TtpEvaluationValidationError(issues);
  }
  return { acceptedPrecisionThreshold, topK, calibrationBins };
}

function calculateExpectedCalibrationError(
  observations: Array<{ confidence: number; correct: boolean }>,
  binCount: number,
): number | null {
  if (observations.length === 0) {
    return null;
  }

  const bins = Array.from({ length: binCount }, () => ({
    confidenceTotal: 0,
    correct: 0,
    count: 0,
  }));
  for (const observation of observations) {
    const binIndex = Math.min(Math.floor(observation.confidence * binCount), binCount - 1);
    const bin = bins[binIndex]!;
    bin.confidenceTotal += observation.confidence;
    bin.correct += observation.correct ? 1 : 0;
    bin.count += 1;
  }

  return bins.reduce((ece, bin) => {
    if (bin.count === 0) {
      return ece;
    }
    const averageConfidence = bin.confidenceTotal / bin.count;
    const accuracy = bin.correct / bin.count;
    return ece + (bin.count / observations.length) * Math.abs(accuracy - averageConfidence);
  }, 0);
}

export function evaluateTtpQuality(
  dataset: TtpEvaluationDataset,
  options: TtpQualityOptions = {},
): TtpQualityReport {
  const configuration = validateOptions(options);
  const answered = dataset.records.filter((record) => !record.abstained);
  const acceptedTop1 = answered.filter((record) =>
    record.acceptedTechniqueIds.includes(record.predictions[0]!.techniqueId),
  ).length;
  const acceptedLabels = dataset.records.reduce(
    (count, record) => count + record.acceptedTechniqueIds.length,
    0,
  );
  const recalledLabelsAtK = dataset.records.reduce((count, record) => {
    const candidates = new Set(
      record.predictions
        .slice(0, configuration.topK)
        .map((prediction) => prediction.techniqueId),
    );
    return (
      count +
      record.acceptedTechniqueIds.filter((techniqueIdValue) => candidates.has(techniqueIdValue))
        .length
    );
  }, 0);

  const acceptedPrecision = answered.length === 0 ? null : acceptedTop1 / answered.length;
  const expectedCalibrationError = calculateExpectedCalibrationError(
    answered.map((record) => ({
      confidence: record.predictions[0]!.modelConfidence,
      correct: record.acceptedTechniqueIds.includes(record.predictions[0]!.techniqueId),
    })),
    configuration.calibrationBins,
  );
  const gatePassed =
    acceptedPrecision !== null &&
    acceptedPrecision + Number.EPSILON >= configuration.acceptedPrecisionThreshold;
  const gateReason =
    acceptedPrecision === null
      ? 'failed: no non-abstained predictions were available'
      : gatePassed
        ? `passed: ${acceptedPrecision.toFixed(4)} >= ${configuration.acceptedPrecisionThreshold.toFixed(4)}`
        : `failed: ${acceptedPrecision.toFixed(4)} < ${configuration.acceptedPrecisionThreshold.toFixed(4)}`;

  return {
    schemaVersion: TTP_EVALUATION_SCHEMA_VERSION,
    datasetId: dataset.datasetId,
    configuration,
    counts: {
      records: dataset.records.length,
      answered: answered.length,
      abstained: dataset.records.length - answered.length,
      acceptedTop1,
      acceptedLabels,
      recalledLabelsAtK,
    },
    metrics: {
      acceptedPrecision,
      coverage: answered.length / dataset.records.length,
      abstentionRate: (dataset.records.length - answered.length) / dataset.records.length,
      topKRecall: recalledLabelsAtK / acceptedLabels,
      expectedCalibrationError,
    },
    gate: {
      metric: 'acceptedPrecision',
      threshold: configuration.acceptedPrecisionThreshold,
      passed: gatePassed,
      reason: gateReason,
    },
  };
}
