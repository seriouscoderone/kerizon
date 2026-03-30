import { describe, it, expect } from 'vitest';
import {
  buildDisseminationPlan,
  classifyMode,
} from '../../src/accountability/dissemination.js';

describe('buildDisseminationPlan', () => {
  it('plan for 3 witnesses has 6 exchanges (2*3)', () => {
    const plan = buildDisseminationPlan(['W1', 'W2', 'W3']);
    expect(plan.exchanges).toHaveLength(6);
  });

  it('plan for 0 witnesses is empty', () => {
    const plan = buildDisseminationPlan([]);
    expect(plan.exchanges).toHaveLength(0);
    expect(plan.maxExchanges).toBe(0);
    expect(plan.bandwidth).toBe(0);
  });

  it('maxExchanges <= 2*N', () => {
    for (const n of [1, 2, 5, 10]) {
      const witnesses = Array.from({ length: n }, (_, i) => `W${i}`);
      const plan = buildDisseminationPlan(witnesses);
      expect(plan.maxExchanges).toBeLessThanOrEqual(2 * n);
      expect(plan.maxExchanges).toBe(2 * n);
    }
  });

  it('bandwidth follows N * ceil(log2(N+1)) formula', () => {
    const witnesses = ['W0', 'W1', 'W2', 'W3', 'W4'];
    const plan = buildDisseminationPlan(witnesses);
    const n = witnesses.length;
    const expected = n * Math.ceil(Math.log2(n + 1));
    expect(plan.bandwidth).toBe(expected);
  });
});

describe('classifyMode', () => {
  it('direct when witnessCount==0 and toad==0', () => {
    expect(classifyMode(0, 0)).toBe('direct');
  });

  it('indirect when witnesses or toad > 0', () => {
    expect(classifyMode(3, 2)).toBe('indirect');
    expect(classifyMode(1, 0)).toBe('indirect');
    expect(classifyMode(0, 1)).toBe('indirect');
  });
});
