import { describe, it, expect } from 'vitest';
import {
  proveSequenceUniqueness,
  proveGapDetection,
} from '../../src/z3/sequence-constraints.js';

describe('Z3: sequence number constraints', () => {
  it('sn admits exactly one valid assignment for KEL of length 1', async () => {
    const result = await proveSequenceUniqueness(1);
    expect(result.result).toBe('unsat'); // no sn[0] != 0 possible
  });

  it('sn admits exactly one valid assignment for KEL of length 5', async () => {
    const result = await proveSequenceUniqueness(5);
    expect(result.result).toBe('unsat'); // sn must be [0,1,2,3,4]
  });

  it('sn admits exactly one valid assignment for KEL of length 10', async () => {
    const result = await proveSequenceUniqueness(10);
    expect(result.result).toBe('unsat');
  });

  it('gaps ARE possible under relaxed monotonicity (proving our strict constraint is necessary)', async () => {
    const result = await proveGapDetection(5);
    expect(result.result).toBe('sat'); // gaps exist under relaxed rules
  });
});
