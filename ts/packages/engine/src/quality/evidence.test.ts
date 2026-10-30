import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { createSourceEvidenceResolver } from './evidence.js';
import { makeStoreMitigations } from '../tools/sandboxed-file.js';

test('evidence resolves exact source excerpts and rejects invented, stale, or escaped citations', () => {
  const root = mkdtempSync('/tmp/threatforest-evidence-');
  try {
    const repo = join(root, 'repo');
    mkdirSync(repo);
    const file = join(repo, 'storage.ts');
    writeFileSync(file, '// storage\r\nbucket.grantRead(workload);\r\n');
    writeFileSync(join(root, 'private.txt'), 'private');
    symlinkSync(join(root, 'private.txt'), join(repo, 'linked.txt'));
    const resolveEvidence = createSourceEvidenceResolver(repo);
    const evidence = { source_type: 'repository', source_ref: 'storage.ts', excerpt: 'bucket.grantRead(workload);' };
    const verified = resolveEvidence(evidence);
    assert.ok(verified);
    assert.equal(verified.line_start, 2);
    assert.equal(verified.line_end, 2);
    assert.match(verified.source_sha256, /^[a-f0-9]{64}$/);
    assert.equal(resolveEvidence({ ...evidence, source_ref: 'missing.ts' }), null);
    assert.equal(resolveEvidence({ ...evidence, excerpt: 'bucket.grantWrite(everyone);' }), null);
    assert.equal(resolveEvidence({ ...evidence, source_type: 'attack_technique', source_ref: 'T1530' }), null);
    assert.equal(resolveEvidence({ ...evidence, source_ref: '../private.txt', excerpt: 'private' }), null);
    assert.equal(resolveEvidence({ ...evidence, source_ref: 'linked.txt', excerpt: 'private' }), null);
    mkdirSync(join(repo, 'run-state'));
    writeFileSync(join(repo, 'run-state', 'scanner_context.json'), '{"invented":"context"}');
    assert.equal(createSourceEvidenceResolver(repo, [join(repo, 'run-state')])({
      ...evidence, source_ref: 'run-state/scanner_context.json', excerpt: 'invented',
    }), null);
    writeFileSync(file, '// different source revision\nbucket.grantRead(workload);\n');
    assert.equal(resolveEvidence({ ...evidence, ...verified }), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('mitigation storage records verified source digests and line locations', async () => {
  const root = mkdtempSync('/tmp/threatforest-evidence-store-');
  try {
    writeFileSync(join(root, 'infra.ts'), 'internetFacing: true\n');
    const file = join(root, 'mitigations.json');
    const store = makeStoreMitigations(file, createSourceEvidenceResolver(root));
    const mitigation = {
      attack_step_id: 'AT001-S1', technique_id: '',
      mitigation_text: 'Restrict the public listener.', implementation_guidance: 'Allow only the application ingress.',
      remediation_type: 'quick_win' as const, priority: 1, control_candidates: [], selected_control_id: '', also_applies_to: [],
      evidence: [{ source_type: 'repository', source_ref: 'infra.ts', excerpt: 'internetFacing: true', relevance: 'This is the exposed entry point.' }],
    };
    await store.invoke({ mitigations: [mitigation] });
    const stored = JSON.parse(readFileSync(file, 'utf8')).mitigations[0].evidence[0];
    assert.match(stored.source_sha256, /^[a-f0-9]{64}$/);
    assert.equal(stored.line_start, 1);
    assert.equal(stored.line_end, 1);
    await assert.rejects(store.invoke({ mitigations: [{
      ...mitigation, evidence: [{ ...mitigation.evidence[0]!, excerpt: 'invented' }],
    }] }), /Unverifiable evidence/);
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')).mitigations[0].evidence[0], stored);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
