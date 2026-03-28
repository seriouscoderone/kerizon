import { describe, it, expect } from 'vitest';
import { proveSaidLengthConstraints, proveSaidDeterminism } from '../../src/z3/said-constraints.js';

describe('Z3: SAID constraints', () => {
  it('SAID length constraints are consistent (valid lengths exist, invalid lengths rejected)', async () => {
    const result = await proveSaidLengthConstraints();
    expect(result.result).toBe('unsat'); // no invalid length can sneak through
  });

  it('SAID computation is deterministic (hash(x) always equals hash(x))', async () => {
    const result = await proveSaidDeterminism();
    expect(result.result).toBe('unsat'); // hash(x) != hash(x) is impossible
  });
});
