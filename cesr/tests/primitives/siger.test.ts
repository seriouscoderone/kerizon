import { describe, it, expect } from 'vitest';
import { Siger } from '../../src/primitives/siger.js';
import { IdrDex } from '../../src/primitives/code-table.js';

describe('Siger', () => {
  // Helper: generate a deterministic 64-byte "signature"
  function fakeSig(fill = 0x42): Uint8Array {
    const sig = new Uint8Array(64);
    sig.fill(fill);
    return sig;
  }

  describe('static create()', () => {
    it('creates with index 0, code A (Ed25519_Sig)', () => {
      const siger = Siger.create({ raw: fakeSig(), index: 0 });
      expect(siger.code).toBe('A');
      expect(siger.index).toBe(0);
      expect(siger.ondex).toBe(0); // os=0 → ondex==index
      expect(siger.raw).toEqual(fakeSig());
      expect(siger.qb64).toHaveLength(88);
      expect(siger.qb64[0]).toBe('A');
    });

    it('creates with index 2', () => {
      const siger = Siger.create({ raw: fakeSig(), index: 2 });
      expect(siger.code).toBe('A');
      expect(siger.index).toBe(2);
      expect(siger.ondex).toBe(2);
      expect(siger.qb64).toHaveLength(88);
    });

    it('creates with index 63 (max for 1-char soft)', () => {
      const siger = Siger.create({ raw: fakeSig(), index: 63 });
      expect(siger.code).toBe('A');
      expect(siger.index).toBe(63);
      expect(siger.qb64).toHaveLength(88);
    });

    it('creates with explicit code B (Ed25519_Crt_Sig)', () => {
      const siger = Siger.create({ raw: fakeSig(), index: 5, code: IdrDex.Ed25519_Crt_Sig });
      expect(siger.code).toBe('B');
      expect(siger.index).toBe(5);
    });

    it('creates with different ondex when code has os > 0', () => {
      // 2A has os=2, so index and ondex each get 2 soft chars
      const siger = Siger.create({
        raw: fakeSig(),
        index: 3,
        ondex: 7,
        code: IdrDex.Ed25519_Big_Sig,
      });
      expect(siger.code).toBe('2A');
      expect(siger.index).toBe(3);
      expect(siger.ondex).toBe(7);
      expect(siger.qb64).toHaveLength(92);
    });

    it('auto-promotes to big code when index > 63', () => {
      const siger = Siger.create({ raw: fakeSig(), index: 64 });
      expect(siger.code).toBe('2A');
      expect(siger.index).toBe(64);
      expect(siger.qb64).toHaveLength(92);
    });
  });

  describe('static fromQb64()', () => {
    it('round-trips through qb64 for index 0', () => {
      const original = Siger.create({ raw: fakeSig(0xaa), index: 0 });
      const restored = Siger.fromQb64(original.qb64);
      expect(restored.code).toBe(original.code);
      expect(restored.index).toBe(original.index);
      expect(restored.ondex).toBe(original.ondex);
      expect(restored.raw).toEqual(original.raw);
      expect(restored.qb64).toBe(original.qb64);
    });

    it('round-trips through qb64 for index 42', () => {
      const original = Siger.create({ raw: fakeSig(0x55), index: 42 });
      const restored = Siger.fromQb64(original.qb64);
      expect(restored.index).toBe(42);
      expect(restored.raw).toEqual(original.raw);
    });

    it('round-trips big index code (2A)', () => {
      const original = Siger.create({
        raw: fakeSig(0x33),
        index: 100,
        ondex: 200,
        code: IdrDex.Ed25519_Big_Sig,
      });
      const restored = Siger.fromQb64(original.qb64);
      expect(restored.code).toBe('2A');
      expect(restored.index).toBe(100);
      expect(restored.ondex).toBe(200);
      expect(restored.raw).toEqual(original.raw);
    });

    it('round-trips index 63 (max single soft char)', () => {
      const original = Siger.create({ raw: fakeSig(0x11), index: 63 });
      const restored = Siger.fromQb64(original.qb64);
      expect(restored.index).toBe(63);
    });
  });

  describe('edge cases', () => {
    it('throws on unknown indexer code', () => {
      expect(() => Siger.fromQb64('ZZ' + 'A'.repeat(86))).toThrow();
    });

    it('ondex defaults to index for os=0 codes', () => {
      const siger = Siger.create({ raw: fakeSig(), index: 10 });
      expect(siger.ondex).toBe(siger.index);
    });

    it('big code with ondex 0 and index 0', () => {
      const siger = Siger.create({
        raw: fakeSig(),
        index: 0,
        ondex: 0,
        code: IdrDex.Ed25519_Big_Sig,
      });
      expect(siger.code).toBe('2A');
      expect(siger.index).toBe(0);
      expect(siger.ondex).toBe(0);
      const restored = Siger.fromQb64(siger.qb64);
      expect(restored.index).toBe(0);
      expect(restored.ondex).toBe(0);
    });
  });
});
