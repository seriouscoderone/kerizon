import { describe, it, expect } from 'vitest';
import { checkWitnessThreshold, checkRotationWitnessThreshold } from '../../src/invariants/witness-threshold.js';

describe('witness threshold invariants', () => {
  it('accepts inception with bt <= witness count', () => {
    const result = checkWitnessThreshold({
      t: 'icp',
      bt: '2',
      b: ['B1111', 'B2222', 'B3333'],
    });
    expect(result.valid).toBe(true);
  });

  it('rejects inception with bt > witness count', () => {
    const result = checkWitnessThreshold({
      t: 'icp',
      bt: '3',
      b: ['B1111', 'B2222'],
    });
    expect(result.valid).toBe(false);
  });

  it('accepts zero threshold with no witnesses', () => {
    const result = checkWitnessThreshold({
      t: 'icp',
      bt: '0',
      b: [],
    });
    expect(result.valid).toBe(true);
  });

  it('rotation: new witness set satisfies threshold after add/cut', () => {
    const result = checkRotationWitnessThreshold(
      ['W1', 'W2', 'W3'],
      { t: 'rot', bt: '2', br: ['W1'], ba: ['W4'] },
    );
    // New set: W2, W3, W4 (3 witnesses), bt = 2 → valid
    expect(result.valid).toBe(true);
  });

  it('rotation: rejects if cuts leave fewer witnesses than threshold', () => {
    const result = checkRotationWitnessThreshold(
      ['W1', 'W2', 'W3'],
      { t: 'rot', bt: '3', br: ['W1', 'W2'], ba: [] },
    );
    // New set: W3 (1 witness), bt = 3 → invalid
    expect(result.valid).toBe(false);
  });

  it('rotation: detects duplicate witnesses', () => {
    const result = checkRotationWitnessThreshold(
      ['W1', 'W2'],
      { t: 'rot', bt: '1', br: [], ba: ['W1'] },
    );
    // W1 already in set, adding again → duplicate
    expect(result.valid).toBe(false);
  });
});
