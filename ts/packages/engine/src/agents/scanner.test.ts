import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ensureScannerStateFile } from './scanner.js';

test('ensureScannerStateFile materializes an empty readable state file', () => {
  const root = mkdtempSync(join(tmpdir(), 'threatforest-scanner-'));
  try {
    const stateFile = join(root, 'nested', 'scanner_context.json');
    ensureScannerStateFile(stateFile);
    assert.equal(readFileSync(stateFile, 'utf8'), '{}\n');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('ensureScannerStateFile preserves pre-seeded business context', () => {
  const root = mkdtempSync(join(tmpdir(), 'threatforest-scanner-'));
  try {
    const stateFile = join(root, 'scanner_context.json');
    const seeded = '{"business_context":{"description":"authoritative"}}\n';
    writeFileSync(stateFile, seeded);
    ensureScannerStateFile(stateFile);
    assert.equal(readFileSync(stateFile, 'utf8'), seeded);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
