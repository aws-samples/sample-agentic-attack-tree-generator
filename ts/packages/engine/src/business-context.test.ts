import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { BusinessContextSchema } from '@threatforest/types';
import { preserveBusinessContext, seedBusinessContext } from './business-context.js';
import { applyScannerReviewEdits } from './agents/hitl.js';
import { LocalFilesystemWorkspace } from './workspace.js';
import { makeSandboxedFileWrite } from './tools/sandboxed-file.js';

const context = BusinessContextSchema.parse({
  description: 'Payment authorisation must remain available.',
  regulatory_frameworks: ['PCI DSS'],
  data_sensitivity: 'regulated_financial',
  cia_priority: ['availability', 'integrity', 'confidentiality'],
});

test('run context seeds all priority fields and rejects a different snapshot on resume', () => {
  const root = mkdtempSync('/tmp/threatforest-business-context-');
  try {
    seedBusinessContext(root, context);
    const state = JSON.parse(readFileSync(join(root, 'scanner_context.json'), 'utf8'));
    assert.deepEqual(state.business_context, context);
    assert.deepEqual(state.compliance_requirements, ['PCI DSS']);
    assert.equal(state.data_sensitivity, 'regulated_financial');
    assert.equal(state.main_cia_risk, 'availability');
    assert.throws(() => seedBusinessContext(root, { ...context, description: 'Changed after run creation' }), /immutable run snapshot/);

    applyScannerReviewEdits(new LocalFilesystemWorkspace(root), 'scanner_context.json', {
      data_sensitivity: 'pii',
      compliance_requirements: ['PCI DSS', 'GDPR'],
    });
    seedBusinessContext(root, context);
    const resumed = JSON.parse(readFileSync(join(root, 'scanner_context.json'), 'utf8'));
    assert.equal(resumed.business_context.data_sensitivity, 'pii');
    assert.deepEqual(resumed.business_context.regulatory_frameworks, ['PCI DSS', 'GDPR']);
    assert.deepEqual(JSON.parse(readFileSync(join(root, 'business_context.snapshot.json'), 'utf8')), context);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scanner write preserves authoritative context even when the model replaces it', async () => {
  const root = mkdtempSync('/tmp/threatforest-business-context-write-');
  try {
    const file = join(root, 'scanner_context.json');
    writeFileSync(file, '{}');
    const writer = makeSandboxedFileWrite([file], (content) =>
      JSON.stringify(preserveBusinessContext(JSON.parse(content), context)),
    );
    await writer.invoke({ path: file, content: JSON.stringify({
      business_context: { description: 'Wrong' },
      data_sensitivity: 'public',
      cia_priority: ['confidentiality', 'integrity', 'availability'],
      compliance_requirements: ['SOC 2'],
      services: ['Payments API'],
    }), mode: 'overwrite' });
    const state = JSON.parse(readFileSync(file, 'utf8'));
    assert.deepEqual(state.business_context, context);
    assert.equal(state.data_sensitivity, context.data_sensitivity);
    assert.deepEqual(state.compliance_requirements, ['PCI DSS', 'SOC 2']);
    assert.deepEqual(state.services, ['Payments API']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
