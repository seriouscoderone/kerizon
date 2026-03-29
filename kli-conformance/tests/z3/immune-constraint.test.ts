import { describe, it, expect } from 'vitest';
import {
  proveImmuneConstraint,
  proveAmpleFormula,
  proveQuorumIntersection,
} from '../../src/z3/immune-constraint.js';

describe('Z3: KAWA witness immune constraint', () => {
  describe('immune constraint soundness', () => {
    it('immune constraint guarantees quorum intersection', async () => {
      const result = await proveImmuneConstraint();
      // Cannot violate intersection when immune holds
      expect(result.details.immuneHoldsButNoIntersection).toBe('unsat');
    });

    it('violating immune constraint allows disjoint quorums', async () => {
      const result = await proveImmuneConstraint();
      // When immune is violated, disjoint quorums ARE possible
      expect(result.details.immuneViolatedAllowsDisjoint).toBe('sat');
    });
  });

  describe('ample() formula', () => {
    it('ample() satisfies immune constraint for n=1..20', async () => {
      const result = await proveAmpleFormula(20);
      expect(result.allSatisfied).toBe(true);

      // Spot-check known values
      const r1 = result.results.find(r => r.n === 1)!;
      expect(r1.ampleValue).toBe(1);
      expect(r1.f).toBe(0);
      expect(r1.immuneSatisfied).toBe(true);

      const r3 = result.results.find(r => r.n === 3)!;
      expect(r3.f).toBe(0);
      expect(r3.immuneSatisfied).toBe(true);

      const r4 = result.results.find(r => r.n === 4)!;
      expect(r4.f).toBe(1);
      expect(r4.immuneSatisfied).toBe(true);

      const r7 = result.results.find(r => r.n === 7)!;
      expect(r7.f).toBe(2);
      expect(r7.immuneSatisfied).toBe(true);

      const r10 = result.results.find(r => r.n === 10)!;
      expect(r10.f).toBe(3);
      expect(r10.immuneSatisfied).toBe(true);
    });

    it('every tested n has immuneSatisfied true', async () => {
      const result = await proveAmpleFormula(20);
      for (const r of result.results) {
        expect(r.immuneSatisfied).toBe(true);
      }
    });
  });

  describe('quorum intersection', () => {
    it('majority threshold implies non-empty intersection', async () => {
      const result = await proveQuorumIntersection();
      expect(result.details.majorityImpliesIntersection).toBe('unsat');
    });

    it('non-majority threshold allows disjoint subsets', async () => {
      const result = await proveQuorumIntersection();
      expect(result.details.nonMajorityAllowsDisjoint).toBe('sat');
    });
  });
});
