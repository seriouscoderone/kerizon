import { describe, it, expect } from 'vitest';
import { Tholder } from '../../src/primitives/tholder.js';

describe('Tholder', () => {
  describe('simple threshold (hex string)', () => {
    it('num returns the parsed integer', () => {
      const th = new Tholder({ sith: '2' });
      expect(th.num).toBe(2);
    });

    it('num handles hex values like "a" (10)', () => {
      const th = new Tholder({ sith: 'a' });
      expect(th.num).toBe(10);
    });

    it('satisfy returns true when enough indices', () => {
      const th = new Tholder({ sith: '2' });
      expect(th.satisfy([0, 1])).toBe(true);
      expect(th.satisfy([0, 1, 2])).toBe(true);
    });

    it('satisfy returns false when not enough indices', () => {
      const th = new Tholder({ sith: '2' });
      expect(th.satisfy([0])).toBe(false);
      expect(th.satisfy([])).toBe(false);
    });

    it('threshold of 1 satisfied by a single index', () => {
      const th = new Tholder({ sith: '1' });
      expect(th.satisfy([0])).toBe(true);
    });

    it('threshold of 0 always satisfied', () => {
      const th = new Tholder({ sith: '0' });
      expect(th.satisfy([])).toBe(true);
    });
  });

  describe('weighted threshold (string[][])', () => {
    it('single clause with equal weights — majority satisfies', () => {
      // 3 signers each with 1/2 weight: need 2 of 3 to reach >= 1
      const th = new Tholder({ sith: [['1/2', '1/2', '1/2']] });
      expect(th.satisfy([0, 1])).toBe(true);
      expect(th.satisfy([0, 2])).toBe(true);
    });

    it('single clause — insufficient weight rejects', () => {
      const th = new Tholder({ sith: [['1/2', '1/2', '1/2']] });
      expect(th.satisfy([0])).toBe(false);
    });

    it('single clause with weight 1 — any single signer suffices', () => {
      const th = new Tholder({ sith: [['1', '1']] });
      expect(th.satisfy([0])).toBe(true);
      expect(th.satisfy([1])).toBe(true);
    });

    it('multiple clauses — all must be satisfied', () => {
      // Two clauses: first needs index 0, second needs index 1
      const th = new Tholder({ sith: [['1', '0'], ['0', '1']] });
      expect(th.satisfy([0, 1])).toBe(true);
      expect(th.satisfy([0])).toBe(false);
      expect(th.satisfy([1])).toBe(false);
    });

    it('mixed weights across clauses', () => {
      // Clause 1: indices 0,1,2 with 1/3 each → need all three
      // Clause 2: index 3 with weight 1 → need index 3
      const th = new Tholder({ sith: [['1/3', '1/3', '1/3'], ['0', '0', '0', '1']] });
      expect(th.satisfy([0, 1, 2, 3])).toBe(true);
      expect(th.satisfy([0, 1, 2])).toBe(false); // clause 2 fails
      expect(th.satisfy([3])).toBe(false); // clause 1 fails
    });
  });

  describe('num accessor', () => {
    it('throws for weighted thresholds', () => {
      const th = new Tholder({ sith: [['1/2', '1/2']] });
      expect(() => th.num).toThrow();
    });
  });
});
