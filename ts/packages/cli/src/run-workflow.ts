/**
 * Workflow runner — TS port of `WorkflowRunner` + `_make_cli_interaction_fn`
 * from `src/threatforest/modules/cli/runner.py`.
 *
 * Drives the engine `runGraph(repoPath, { runDir, frameworks, interactionFn })`
 * and supplies a terminal HITL `interactionFn` that handles the scanner-review
 * and interviewer interrupts exactly as the Python did (Rich table → plain
 * table; `console.input("> ")` → readline). The run directory is created under
 * `.threatforest/runs/` to mirror `server.registry.create_run_directory`.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import pc from 'picocolors';
import {
  runGraph,
  type RunGraphResult,
  type InteractionFn,
  type InteractionResponse,
} from '@threatforest/engine';
import * as display from './display.js';

/** Read a single line from the terminal (analog of rich console.input). */
async function ask(prompt: string): Promise<string | null> {
  const rl = createInterface({ input, output });
  try {
    return await rl.question(prompt);
  } catch {
    return null; // EOF / Ctrl-C
  } finally {
    rl.close();
  }
}

/** Render scanner findings as a plain table and collect an edit/confirm response. */
async function handleScannerReview(
  interruptId: string,
  reason: Record<string, unknown>,
): Promise<InteractionResponse[] | null> {
  const scanner = (reason.scanner_data ?? {}) as Record<string, unknown>;
  const get = (k: string): string => String(scanner[k] ?? '');
  const list = (k: string): string => {
    const v = scanner[k];
    return Array.isArray(v) && v.length ? (v as unknown[]).join(', ') : 'none';
  };
  const filesAnalyzed = Array.isArray(scanner.files_analyzed) ? scanner.files_analyzed.length : 0;

  display.blank();
  const rows: [string, string][] = [
    ['Cloud Provider', get('cloud_provider') || 'unknown'],
    ['Tech Stack', get('tech_stack')],
    ['Industry', get('industry') || 'not detected'],
    ['Services', list('services')],
    ['Auth Mechanisms', list('auth_mechanisms')],
    ['Compliance', list('compliance_requirements')],
    ['Data Sensitivity', get('data_sensitivity') || 'not detected'],
    ['Files Analyzed', String(filesAnalyzed)],
  ];
  const body = rows
    .map(([k, v]) => `${pc.bold(k.padEnd(16))} ${v}`)
    .join('\n');
  display.panel(body, { title: 'Scanner Findings', color: pc.cyan });
  display.blank();
  display.print(pc.dim('Press Enter to confirm, or type edits as JSON (e.g. {"industry": "healthcare"}).'));
  display.print(pc.dim("Type 'skip' to proceed without review."));
  display.blank();

  const resp = await ask(pc.cyan('> '));
  if (resp === null) return null;
  const trimmed = resp.trim().toLowerCase();
  if (!resp || trimmed === 'skip' || trimmed === 's') return null;
  let response: unknown = resp;
  if (!resp.trim() || ['y', 'yes', 'confirm', 'ok'].includes(trimmed)) {
    response = JSON.stringify({ confirmed_only: true });
  }
  return [{ interruptResponse: { interruptId, response } }];
}

/** The terminal HITL interaction function (port of _make_cli_interaction_fn). */
export function makeCliInteractionFn(): InteractionFn {
  return async (interrupts) => {
    for (const interrupt of interrupts) {
      const reason = interrupt.reason ?? {};
      const phase = (reason.phase as string) ?? 'interviewer';

      if (phase === 'scanner_review') {
        return handleScannerReview(interrupt.id, reason);
      }

      display.blank();
      display.panel(String(reason.message ?? 'The interviewer has questions for you.'), {
        title: 'Context Validation',
        color: pc.cyan,
      });

      const questions = (reason.questions as string[] | undefined) ?? [];
      questions.forEach((q, i) => display.print(`  ${pc.bold(String(i + 1) + '.')} ${q}`));

      display.blank();
      display.print(pc.dim("Type your response, 'skip' to proceed, or 'back' to edit scanner findings."));
      display.blank();

      const resp = await ask(pc.cyan('> '));
      if (resp === null) return null;
      const trimmed = resp.trim().toLowerCase();
      if (!resp || ['skip', 'done', 's'].includes(trimmed)) return null;
      if (trimmed === 'back') {
        return [{ interruptResponse: { interruptId: interrupt.id, response: '__back__' } }];
      }
      return [{ interruptResponse: { interruptId: interrupt.id, response: resp } }];
    }
    return null;
  };
}

/**
 * Run the full workflow via the engine graph. Creates a run dir under
 * `.threatforest/runs/<sanitized-project>/<timestamp>` and returns the engine
 * result (status: 'success' | 'failed', output_dir, error?).
 */
export async function runFullWorkflow(
  projectPath: string,
  frameworks: string[] | null,
): Promise<RunGraphResult> {
  const runsRoot = join(process.cwd(), '.threatforest', 'runs');
  const runDir = join(runsRoot, sanitize(projectPath), new Date().toISOString().replace(/[:.]/g, '-'));
  mkdirSync(runDir, { recursive: true });

  return runGraph(projectPath, {
    runDir,
    frameworks,
    interactionFn: makeCliInteractionFn(),
  });
}

function sanitize(p: string): string {
  return p.replace(/[^a-zA-Z0-9_-]+/g, '_').replace(/^_+|_+$/g, '') || 'project';
}
