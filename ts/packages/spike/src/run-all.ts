/**
 * WS-0 spike runner. Spike 1 (Graph interrupt/resume) is the hard gate and runs
 * with no external dependencies. Spike 2 (structured output) needs Bedrock and is
 * skipped with a clear notice if AWS credentials are unavailable, so the gate can
 * still be evaluated offline.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

function run(script: string): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ['--import', 'tsx/esm', join(here, script)],
      { stdio: 'inherit' },
    );
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

async function hasAwsCreds(): Promise<boolean> {
  return new Promise((resolve) => {
    const c = spawn('aws', ['sts', 'get-caller-identity'], { stdio: 'ignore' });
    c.on('exit', (code) => resolve(code === 0));
    c.on('error', () => resolve(false));
  });
}

async function main(): Promise<void> {
  console.log('=== WS-0 Spike 1: Graph interrupt → resume (HARD GATE) ===');
  const s1 = await run('graph-interrupt.ts');
  if (s1 !== 0) {
    console.error('\nHARD GATE FAILED on Spike 1. Stop the full port; revisit HITL design.');
    process.exit(1);
  }

  console.log('\n=== WS-0 Spike 2: structured output on Bedrock ===');
  if (!(await hasAwsCreds())) {
    console.log('⚠️  Skipping Spike 2 — no AWS credentials. Re-run with Bedrock access.');
    console.log('\nSpike 1 (the hard gate) PASSED.');
    return;
  }
  const s2 = await run('structured-output.ts');
  if (s2 !== 0) {
    console.error('\nSpike 2 failed (Bedrock structured output). Investigate before WS-3.');
    process.exit(1);
  }
  console.log('\n✅ All WS-0 spikes passed.');
}

main();
