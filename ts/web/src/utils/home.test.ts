import { expect, test } from 'vitest';
import {
  PIPELINE_STAGES,
  buildConfigVerifiedSignature,
  pickHomeCta,
} from './home';

test('pickHomeCta: unconfigured user always routes to configure', () => {
  expect(pickHomeCta(false, false)).toBe('configure');
  expect(pickHomeCta(false, true)).toBe('configure');
});

test('pickHomeCta: configured user with no apps is nudged to create the first one', () => {
  expect(pickHomeCta(true, false)).toBe('create-first-app');
});

test('pickHomeCta: configured user with apps sees the run panel', () => {
  expect(pickHomeCta(true, true)).toBe('run');
});

test('PIPELINE_STAGES describes the six-stage pipeline in order', () => {
  const titles = PIPELINE_STAGES.map((s) => s.title);
  expect(titles).toEqual([
    'Repository Analysis',
    'Threat Parsing',
    'Attack Tree Generation',
    'TTP Enrichment',
    'Mitigation Mapping',
    'Dashboard Generation',
  ]);
  for (const stage of PIPELINE_STAGES) {
    expect(stage.title.length).toBeGreaterThan(0);
    expect(stage.description.length).toBeGreaterThan(0);
  }
});

test('buildConfigVerifiedSignature: matches the exact shape the Configure page writes', () => {
  const sig = buildConfigVerifiedSignature({
    model_id: 'global.anthropic.claude-opus-4-7',
    aws_region: 'eu-west-2',
  });
  expect(sig).toBe(
    JSON.stringify({
      provider: 'AWS Bedrock',
      model_id: 'global.anthropic.claude-opus-4-7',
      aws_region: 'eu-west-2',
      aws_profile: '',
    }),
  );
});

test('buildConfigVerifiedSignature: nulls and undefineds normalize to empty strings', () => {
  const a = buildConfigVerifiedSignature({ model_id: null, aws_region: undefined });
  const b = buildConfigVerifiedSignature({ model_id: '', aws_region: '' });
  expect(a).toBe(b);
});

test('buildConfigVerifiedSignature: any drift in inputs changes the signature', () => {
  const base = buildConfigVerifiedSignature({ model_id: 'm1', aws_region: 'r1' });
  expect(buildConfigVerifiedSignature({ model_id: 'm2', aws_region: 'r1' })).not.toBe(base);
  expect(buildConfigVerifiedSignature({ model_id: 'm1', aws_region: 'r2' })).not.toBe(base);
});
