import { describe, it, expect } from 'vitest';
import { checkAccountability, ample } from '../../src/accountability/kawa.js';

describe('checkAccountability', () => {
  it('met when receiptCount >= toad', () => {
    const result = checkAccountability(3, 3);
    expect(result.met).toBe(true);
    expect(result.count).toBe(3);
    expect(result.threshold).toBe(3);
  });

  it('not met when receiptCount < toad', () => {
    const result = checkAccountability(1, 3);
    expect(result.met).toBe(false);
    expect(result.count).toBe(1);
    expect(result.threshold).toBe(3);
  });

  it('toad=0 is always met', () => {
    const result = checkAccountability(0, 0);
    expect(result.met).toBe(true);
  });
});

describe('ample', () => {
  it('ample(1) = 1', () => {
    expect(ample(1)).toBe(1);
  });

  it('ample(3) = 2', () => {
    expect(ample(3)).toBe(2);
  });

  it('ample(6) = 4', () => {
    expect(ample(6)).toBe(4);
  });

  it('ample(10) = 7', () => {
    expect(ample(10)).toBe(7);
  });

  it('immune constraint: ample(n) > floor((n-1)/3) for n=1..20', () => {
    for (let n = 1; n <= 20; n++) {
      const a = ample(n);
      const byzantine = Math.floor((n - 1) / 3);
      expect(a).toBeGreaterThan(byzantine);
    }
  });
});
