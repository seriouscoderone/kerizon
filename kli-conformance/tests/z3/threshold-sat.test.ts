import { describe, it, expect } from 'vitest';
import {
  proveSimpleThreshold,
  proveThresholdImpossible,
  proveFractionalThreshold,
  proveWitnessTally,
} from '../../src/z3/threshold-constraints.js';

describe('Z3: threshold constraints', () => {
  describe('simple threshold', () => {
    it('2-of-3 is satisfiable', async () => {
      const result = await proveSimpleThreshold(3, 2);
      expect(result.result).toBe('sat');
      expect(result.satisfyingSet).toBeTruthy();
      const count = result.satisfyingSet!.filter(Boolean).length;
      expect(count).toBeGreaterThanOrEqual(2);
    });

    it('1-of-1 is satisfiable', async () => {
      const result = await proveSimpleThreshold(1, 1);
      expect(result.result).toBe('sat');
    });

    it('3-of-2 is impossible', async () => {
      const result = await proveThresholdImpossible(2, 3);
      expect(result.result).toBe('unsat');
    });

    it('0-of-0 is trivially satisfiable', async () => {
      const result = await proveSimpleThreshold(0, 0);
      expect(result.result).toBe('sat');
    });
  });

  describe('fractional threshold', () => {
    it('any 2-of-3 with equal weights [1/2, 1/2, 1/2] is satisfiable', async () => {
      const result = await proveFractionalThreshold([
        [[1, 2], [1, 2], [1, 2]],
      ]);
      expect(result.result).toBe('sat');
    });

    it('all-of-3 with weight 1/3 each requires all signatures', async () => {
      // Each key contributes 1/3, so all 3 must sign to reach >= 1
      const result = await proveFractionalThreshold([
        [[1, 3], [1, 3], [1, 3]],
      ]);
      expect(result.result).toBe('sat');
      // All must be true
      if (result.satisfyingSet) {
        expect(result.satisfyingSet.every(Boolean)).toBe(true);
      }
    });

    it('impossible threshold with insufficient weights', async () => {
      // Two keys with weight 1/4 each, max sum = 1/2 < 1
      const result = await proveFractionalThreshold([
        [[1, 4], [1, 4]],
      ]);
      expect(result.result).toBe('unsat');
    });

    it('multi-clause: both clauses must be satisfied', async () => {
      // Clause 1: key 0 with weight 1
      // Clause 2: key 1 with weight 1
      // Both keys must sign
      const result = await proveFractionalThreshold([
        [[1, 1], [0, 1]],
        [[0, 1], [1, 1]],
      ]);
      expect(result.result).toBe('sat');
      if (result.satisfyingSet) {
        expect(result.satisfyingSet).toEqual([true, true]);
      }
    });
  });

  describe('witness tally', () => {
    it('toad=2 with 3 witnesses is satisfiable', async () => {
      const result = await proveWitnessTally(3, 2);
      expect(result.result).toBe('sat');
    });

    it('toad=5 with 3 witnesses is impossible', async () => {
      const result = await proveWitnessTally(3, 5);
      expect(result.result).toBe('unsat');
    });
  });
});
