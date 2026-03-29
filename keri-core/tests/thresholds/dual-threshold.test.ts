import { describe, it, expect } from 'vitest';
import { Tholder } from '@kerizon/cesr';
import { checkDualThreshold } from '../../src/thresholds/dual-threshold.js';

describe('checkDualThreshold', () => {
  it('returns satisfied when both thresholds are met', () => {
    const signing = new Tholder({ sith: '2' });
    const rotation = new Tholder({ sith: '1' });
    const result = checkDualThreshold(signing, rotation, [0, 1], [0]);
    expect(result.satisfied).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('returns not satisfied when signing threshold is not met', () => {
    const signing = new Tholder({ sith: '3' });
    const rotation = new Tholder({ sith: '1' });
    const result = checkDualThreshold(signing, rotation, [0, 1], [0]);
    expect(result.satisfied).toBe(false);
    expect(result.reason).toContain('signing');
  });

  it('returns not satisfied when rotation threshold is not met', () => {
    const signing = new Tholder({ sith: '1' });
    const rotation = new Tholder({ sith: '2' });
    const result = checkDualThreshold(signing, rotation, [0], [0]);
    expect(result.satisfied).toBe(false);
    expect(result.reason).toContain('rotation');
  });

  it('returns not satisfied when neither threshold is met', () => {
    const signing = new Tholder({ sith: '3' });
    const rotation = new Tholder({ sith: '2' });
    const result = checkDualThreshold(signing, rotation, [0], [0]);
    expect(result.satisfied).toBe(false);
    // signing is checked first, so reason should mention signing
    expect(result.reason).toContain('signing');
  });

  it('supports weighted signing thresholds', () => {
    const signing = new Tholder({ sith: [['1/2', '1/2', '1']] });
    const rotation = new Tholder({ sith: '1' });
    // indices [0, 1] → 1/2 + 1/2 = 1 >= 1 → satisfied
    const result = checkDualThreshold(signing, rotation, [0, 1], [0]);
    expect(result.satisfied).toBe(true);
  });

  it('only checks signing when rotationThreshold is null (inception)', () => {
    const signing = new Tholder({ sith: '1' });
    const result = checkDualThreshold(signing, null, [0], []);
    expect(result.satisfied).toBe(true);
    expect(result.reason).toBeUndefined();
  });
});
