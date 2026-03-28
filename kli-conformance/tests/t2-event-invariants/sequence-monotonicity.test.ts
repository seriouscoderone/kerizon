import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  sequenceMonotonicityProperty,
  inceptionSnZero,
  checkSequenceMonotonicity,
} from '../../src/invariants/sequence.js';

const NUM_RUNS = 500;

describe('sequence monotonicity invariants', () => {
  it('generated KELs always have monotonic sn', () => {
    fc.assert(sequenceMonotonicityProperty, { numRuns: NUM_RUNS });
  });

  it('inception event always has sn == 0', () => {
    fc.assert(inceptionSnZero, { numRuns: NUM_RUNS });
  });

  it('detects sn gap violations', () => {
    const result = checkSequenceMonotonicity([
      { sn: 0 },
      { sn: 1 },
      { sn: 3 }, // gap!
    ]);
    expect(result.valid).toBe(false);
    expect(result.violation).toContain('expected 2');
  });

  it('detects non-zero inception sn', () => {
    const result = checkSequenceMonotonicity([{ sn: 1 }]);
    expect(result.valid).toBe(false);
    expect(result.violation).toContain('expected 0');
  });

  it('accepts empty event list', () => {
    expect(checkSequenceMonotonicity([]).valid).toBe(true);
  });

  it('accepts single inception event', () => {
    expect(checkSequenceMonotonicity([{ sn: 0 }]).valid).toBe(true);
  });
});
