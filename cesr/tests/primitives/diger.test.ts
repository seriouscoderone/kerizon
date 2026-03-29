import { describe, it, expect } from 'vitest';
import { Diger } from '../../src/primitives/diger.js';
import { MtrDex } from '../../src/primitives/code-table.js';

describe('Diger', () => {
  const testData = new TextEncoder().encode('Hello, KERI!');

  describe('static digest()', () => {
    it('defaults to Blake3-256 (code E)', () => {
      const d = Diger.digest(testData);
      expect(d.code).toBe('E');
      expect(d.raw).toHaveLength(32);
      expect(d.qb64).toHaveLength(44);
      expect(d.qb64[0]).toBe('E');
    });

    it('produces Blake2b-256 digest (code F)', () => {
      const d = Diger.digest(testData, MtrDex.Blake2b_256);
      expect(d.code).toBe('F');
      expect(d.raw).toHaveLength(32);
      expect(d.qb64[0]).toBe('F');
    });

    it('produces Blake2s-256 digest (code G)', () => {
      const d = Diger.digest(testData, MtrDex.Blake2s_256);
      expect(d.code).toBe('G');
      expect(d.raw).toHaveLength(32);
      expect(d.qb64[0]).toBe('G');
    });

    it('produces SHA3-256 digest (code H)', () => {
      const d = Diger.digest(testData, MtrDex.SHA3_256);
      expect(d.code).toBe('H');
      expect(d.raw).toHaveLength(32);
      expect(d.qb64[0]).toBe('H');
    });

    it('produces SHA2-256 digest (code I)', () => {
      const d = Diger.digest(testData, MtrDex.SHA2_256);
      expect(d.code).toBe('I');
      expect(d.raw).toHaveLength(32);
      expect(d.qb64[0]).toBe('I');
    });

    it('is deterministic — same input produces same output', () => {
      const d1 = Diger.digest(testData);
      const d2 = Diger.digest(testData);
      expect(d1.qb64).toBe(d2.qb64);
      expect(d1.raw).toEqual(d2.raw);
    });

    it('different data produces different digests', () => {
      const d1 = Diger.digest(testData);
      const d2 = Diger.digest(new TextEncoder().encode('Different data'));
      expect(d1.qb64).not.toBe(d2.qb64);
    });

    it('throws for unsupported digest code', () => {
      expect(() => Diger.digest(testData, MtrDex.Ed25519)).toThrow();
    });
  });

  describe('compare()', () => {
    it('returns true when data matches the digest', () => {
      const d = Diger.digest(testData);
      expect(d.compare(testData)).toBe(true);
    });

    it('returns false when data does not match', () => {
      const d = Diger.digest(testData);
      const other = new TextEncoder().encode('Wrong data');
      expect(d.compare(other)).toBe(false);
    });

    it('works for all supported codes', () => {
      const codes = [
        MtrDex.Blake3_256,
        MtrDex.Blake2b_256,
        MtrDex.Blake2s_256,
        MtrDex.SHA3_256,
        MtrDex.SHA2_256,
      ];
      for (const code of codes) {
        const d = Diger.digest(testData, code);
        expect(d.compare(testData)).toBe(true);
        expect(d.compare(new Uint8Array(1))).toBe(false);
      }
    });
  });

  describe('construct from qb64', () => {
    it('round-trips through qb64', () => {
      const d1 = Diger.digest(testData);
      const d2 = new Diger({ qb64: d1.qb64 });
      expect(d2.code).toBe(d1.code);
      expect(d2.raw).toEqual(d1.raw);
      expect(d2.compare(testData)).toBe(true);
    });
  });
});
