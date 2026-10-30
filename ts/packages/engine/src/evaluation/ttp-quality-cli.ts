#!/usr/bin/env node
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  DEFAULT_ACCEPTED_PRECISION_THRESHOLD,
  DEFAULT_CALIBRATION_BINS,
  DEFAULT_TOP_K,
  evaluateTtpQuality,
  loadTtpEvaluationDataset,
  type TtpQualityReport,
} from './ttp-quality.js';

interface CliOptions {
  datasetPath: string;
  acceptedPrecisionThreshold: number;
  topK: number;
  calibrationBins: number;
  json: boolean;
}

const usage = `Usage:
  npm run evaluate:ttp -- --dataset <dataset.json|dataset.jsonl> [options]

Options:
  --precision-threshold <0..1>  Accepted top-1 precision gate (default: 0.70)
  --top-k <integer>             Candidate recall depth (default: 3)
  --calibration-bins <integer>  ECE bins from 1 to 100 (default: 10)
  --json                        Emit machine-readable JSON
  --help                        Show this help
`;

function requireValue(args: string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function parseNumber(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${flag} must be a number`);
  }
  return parsed;
}

export function parseCliArguments(args: string[]): CliOptions | { help: true } {
  let datasetPath: string | undefined;
  let acceptedPrecisionThreshold = DEFAULT_ACCEPTED_PRECISION_THRESHOLD;
  let topK = DEFAULT_TOP_K;
  let calibrationBins = DEFAULT_CALIBRATION_BINS;
  let json = false;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    switch (argument) {
      case '--dataset':
        datasetPath = requireValue(args, index, argument);
        index += 1;
        break;
      case '--precision-threshold':
        acceptedPrecisionThreshold = parseNumber(requireValue(args, index, argument), argument);
        index += 1;
        break;
      case '--top-k':
        topK = parseNumber(requireValue(args, index, argument), argument);
        index += 1;
        break;
      case '--calibration-bins':
        calibrationBins = parseNumber(requireValue(args, index, argument), argument);
        index += 1;
        break;
      case '--json':
        json = true;
        break;
      case '--help':
      case '-h':
        return { help: true };
      default:
        throw new Error(`unknown argument: ${argument}`);
    }
  }

  if (datasetPath === undefined) {
    throw new Error('--dataset is required');
  }
  return {
    datasetPath,
    acceptedPrecisionThreshold,
    topK,
    calibrationBins,
    json,
  };
}

function formatMetric(value: number | null): string {
  return value === null ? 'n/a' : value.toFixed(4);
}

export function formatHumanReport(report: TtpQualityReport): string {
  return [
    `TTP quality evaluation: ${report.datasetId}`,
    `Records: ${report.counts.records} (${report.counts.answered} answered, ${report.counts.abstained} abstained)`,
    `Accepted precision: ${formatMetric(report.metrics.acceptedPrecision)}`,
    `Coverage: ${formatMetric(report.metrics.coverage)}`,
    `Abstention rate: ${formatMetric(report.metrics.abstentionRate)}`,
    `Top-${report.configuration.topK} recall: ${formatMetric(report.metrics.topKRecall)}`,
    `Calibration error (ECE): ${formatMetric(report.metrics.expectedCalibrationError)}`,
    `Precision gate: ${report.gate.reason}`,
  ].join('\n');
}

export async function runCli(
  args: string[],
  output: Pick<NodeJS.WriteStream, 'write'> = process.stdout,
  errorOutput: Pick<NodeJS.WriteStream, 'write'> = process.stderr,
): Promise<number> {
  try {
    const options = parseCliArguments(args);
    if ('help' in options) {
      output.write(usage);
      return 0;
    }
    const dataset = await loadTtpEvaluationDataset(options.datasetPath);
    const report = evaluateTtpQuality(dataset, {
      acceptedPrecisionThreshold: options.acceptedPrecisionThreshold,
      topK: options.topK,
      calibrationBins: options.calibrationBins,
    });
    output.write(`${options.json ? JSON.stringify(report, null, 2) : formatHumanReport(report)}\n`);
    return report.gate.passed ? 0 : 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errorOutput.write(`TTP evaluation failed: ${message}\n`);
    return 1;
  }
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(invokedPath)).href
) {
  process.exitCode = await runCli(process.argv.slice(2));
}
