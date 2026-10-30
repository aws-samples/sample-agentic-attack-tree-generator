import { expect, test } from 'vitest';
import { topThreats } from './risk-posture';

test('multiple trees join by threat ID and legacy labels do not duplicate a threat', () => {
  const threats = [
    { id: 'TS001', title: 'First threat', priority: 'low' },
    { id: 'TS002', title: 'Second threat', priority: 'high' },
  ];
  const trees = [
    { threat_id: 'TS001', tree_id: 'AT001' },
    { threat_id: 'TS001 [AttackTree - 2]' },
    { threat_id: 'TS002', tree_id: 'AT003' },
  ];
  expect(topThreats(threats, trees)).toEqual([
    { id: 'TS002', index: 2, title: 'Second threat', severity: 'high' },
    { id: 'TS001', index: 0, title: 'First threat', severity: 'low' },
  ]);
});
