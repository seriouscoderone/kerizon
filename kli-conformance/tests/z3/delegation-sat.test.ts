import { describe, it, expect } from 'vitest';
import {
  proveBidirectionalPeg,
  proveSealExactMatch,
} from '../../src/z3/delegation.js';

describe('Z3: delegation constraints', () => {
  it('delegation requires BOTH di match AND seal (bidirectional peg)', async () => {
    const result = await proveBidirectionalPeg();
    expect(result.bothDirectionsRequired).toBe(true);

    // Neither direction → invalid
    expect(result.details.neitherDirection).toBe('unsat');
    // Only di → invalid
    expect(result.details.onlyDi).toBe('unsat');
    // Only seal → invalid
    expect(result.details.onlySeal).toBe('unsat');
    // Both → valid
    expect(result.details.bothDirections).toBe('sat');
  });

  it('delegation seal must exactly match all three fields (i, s, d)', async () => {
    const result = await proveSealExactMatch();
    expect(result.allFieldsRequired).toBe(true);

    // All match → valid
    expect(result.details.allMatch).toBe('sat');
    // Any mismatch → invalid
    expect(result.details.prefixMismatch).toBe('unsat');
    expect(result.details.snMismatch).toBe('unsat');
    expect(result.details.saidMismatch).toBe('unsat');
  });
});
