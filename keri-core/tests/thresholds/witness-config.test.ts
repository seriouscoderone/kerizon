import { describe, it, expect } from 'vitest';
import {
  buildWitnessConfig,
  applyWitnessChanges,
  enoughReceipts,
} from '../../src/thresholds/witness-config.js';

describe('buildWitnessConfig', () => {
  it('builds a config from a witness list and toad', () => {
    const config = buildWitnessConfig(['w1', 'w2', 'w3'], 2);
    expect(config.witnesses).toEqual(['w1', 'w2', 'w3']);
    expect(config.toad).toBe(2);
  });

  it('rejects toad greater than witness count', () => {
    expect(() => buildWitnessConfig(['w1'], 2)).toThrow('toad (2) > witness count (1)');
  });

  it('rejects negative toad', () => {
    expect(() => buildWitnessConfig([], -1)).toThrow('toad must be non-negative');
  });

  it('rejects duplicate witnesses', () => {
    expect(() => buildWitnessConfig(['w1', 'w1'], 1)).toThrow('duplicate witnesses');
  });

  it('allows direct mode: toad=0 with empty witness list', () => {
    const config = buildWitnessConfig([], 0);
    expect(config.witnesses).toEqual([]);
    expect(config.toad).toBe(0);
  });
});

describe('applyWitnessChanges', () => {
  const base = buildWitnessConfig(['w1', 'w2', 'w3'], 2);

  it('applies removals before additions', () => {
    const updated = applyWitnessChanges(base, ['w1'], ['w4']);
    expect(updated.witnesses).toEqual(['w2', 'w3', 'w4']);
    expect(updated.toad).toBe(2);
  });

  it('updates toad when provided', () => {
    const updated = applyWitnessChanges(base, [], ['w4'], 3);
    expect(updated.witnesses).toEqual(['w1', 'w2', 'w3', 'w4']);
    expect(updated.toad).toBe(3);
  });

  it('rejects adding an existing witness', () => {
    expect(() => applyWitnessChanges(base, [], ['w2'])).toThrow('cannot add "w2"');
  });

  it('rejects removing a non-existent witness', () => {
    expect(() => applyWitnessChanges(base, ['w9'], [])).toThrow('cannot remove "w9"');
  });
});

describe('enoughReceipts', () => {
  const config = buildWitnessConfig(['w1', 'w2', 'w3'], 2);

  it('returns true when receipt count >= toad', () => {
    expect(enoughReceipts(config, [0, 1])).toBe(true);
    expect(enoughReceipts(config, [0, 1, 2])).toBe(true);
  });

  it('returns false when receipt count < toad', () => {
    expect(enoughReceipts(config, [0])).toBe(false);
    expect(enoughReceipts(config, [])).toBe(false);
  });
});
