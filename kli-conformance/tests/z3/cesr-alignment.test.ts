import { describe, it, expect } from 'vitest';
import {
  proveQuadletAlignment,
  provePadSizeFormula,
  proveCodeSizeAlignment,
  proveColdStartTritetBijection,
} from '../../src/z3/cesr-alignment.js';

describe('Z3: CESR structural alignment', () => {
  describe('quadlet alignment', () => {
    it('4 T-domain chars = 3 B-domain bytes always holds', async () => {
      const result = await proveQuadletAlignment();
      expect(result.details.ratioHolds).toBe('sat');
    });

    it('ratio violation is impossible', async () => {
      const result = await proveQuadletAlignment();
      expect(result.details.ratioViolationImpossible).toBe('unsat');
    });
  });

  describe('pad size formula', () => {
    it('ps = (3 - (N % 3)) % 3 holds for byte lengths 0..11', async () => {
      const result = await provePadSizeFormula();
      expect(result.allCorrect).toBe(true);
    });

    it('pad size is always 0, 1, or 2', async () => {
      const result = await provePadSizeFormula();
      for (const r of result.results) {
        expect(r.expectedPad).toBeGreaterThanOrEqual(0);
        expect(r.expectedPad).toBeLessThanOrEqual(2);
        expect(r.formulaHolds).toBe(true);
      }
    });

    it('pad size cycles: 0,2,1,0,2,1,...', async () => {
      const result = await provePadSizeFormula();
      const expectedCycle = [0, 2, 1];
      for (const r of result.results) {
        expect(r.expectedPad).toBe(expectedCycle[r.rawLen % 3]);
      }
    });
  });

  describe('code size alignment by pad size', () => {
    it('ps=0 requires cs divisible by 4', async () => {
      const result = await proveCodeSizeAlignment();
      const ps0 = result.results.find(r => r.padSize === 0)!;
      expect(ps0.expectedCsMod4).toBe(0);
      expect(ps0.constraintHolds).toBe(true);
    });

    it('ps=1 requires cs % 4 == 1', async () => {
      const result = await proveCodeSizeAlignment();
      const ps1 = result.results.find(r => r.padSize === 1)!;
      expect(ps1.expectedCsMod4).toBe(1);
      expect(ps1.constraintHolds).toBe(true);
    });

    it('ps=2 requires cs % 4 == 2', async () => {
      const result = await proveCodeSizeAlignment();
      const ps2 = result.results.find(r => r.padSize === 2)!;
      expect(ps2.expectedCsMod4).toBe(2);
      expect(ps2.constraintHolds).toBe(true);
    });

    it('all pad sizes produce correct alignment', async () => {
      const result = await proveCodeSizeAlignment();
      expect(result.allCorrect).toBe(true);
    });
  });

  describe('cold start tritet bijection', () => {
    it('8 tritet values can map to 8 distinct frame types', async () => {
      const result = await proveColdStartTritetBijection();
      expect(result.details.allDistinct).toBe('sat');
    });

    it('collision is impossible under distinctness requirement', async () => {
      const result = await proveColdStartTritetBijection();
      expect(result.details.collisionImpossible).toBe('unsat');
    });

    it('exactly 8 valid tritet values exist (0-7)', async () => {
      const result = await proveColdStartTritetBijection();
      expect(result.details.exactlyEight).toBe('unsat');
    });
  });
});
