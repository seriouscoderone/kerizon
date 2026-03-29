import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { Matter } from '../../src/primitives/matter.js';
import { MtrDex, MtrSizage } from '../../src/primitives/code-table.js';

/**
 * Compute expected raw byte size for a given Matter code.
 * raw_bytes = floor((fs - hs - ss) * 3 / 4)
 */
function rawSizeForCode(code: string): number {
  const s = MtrSizage[code];
  if (!s) throw new Error(`Unknown code: ${code}`);
  return Math.floor(((s.fs - s.hs - s.ss) * 3) / 4);
}

describe('Matter', () => {
  describe('construct from (code, raw)', () => {
    it('produces correct qb64 for Ed25519 verfer (code D)', () => {
      const raw = new Uint8Array(32);
      crypto.getRandomValues(raw);

      const m = new Matter({ code: MtrDex.Ed25519, raw });

      expect(m.code).toBe('D');
      expect(m.raw).toEqual(raw);
      expect(m.qb64).toHaveLength(44);
      expect(m.qb64[0]).toBe('D');
    });

    it('produces correct qb64 for Ed25519_Sig (code 0B)', () => {
      const raw = new Uint8Array(64);
      crypto.getRandomValues(raw);

      const m = new Matter({ code: MtrDex.Ed25519_Sig, raw });

      expect(m.code).toBe('0B');
      expect(m.raw).toEqual(raw);
      expect(m.qb64).toHaveLength(88);
      expect(m.qb64.startsWith('0B')).toBe(true);
    });

    it('produces correct qb64 for Salt_128 (code 0A)', () => {
      const raw = new Uint8Array(16);
      crypto.getRandomValues(raw);

      const m = new Matter({ code: MtrDex.Salt_128, raw });

      expect(m.code).toBe('0A');
      expect(m.qb64).toHaveLength(24);
      expect(m.qb64.startsWith('0A')).toBe(true);
    });

    it('produces correct qb64 for DateTime (code 1AAG)', () => {
      const raw = new Uint8Array(24);
      crypto.getRandomValues(raw);

      const m = new Matter({ code: MtrDex.DateTime, raw });

      expect(m.code).toBe('1AAG');
      expect(m.qb64).toHaveLength(36);
      expect(m.qb64.startsWith('1AAG')).toBe(true);
    });
  });

  describe('construct from qb64', () => {
    it('recovers code and raw from Ed25519 qb64', () => {
      const raw = new Uint8Array(32);
      crypto.getRandomValues(raw);

      const m1 = new Matter({ code: MtrDex.Ed25519, raw });
      const m2 = new Matter({ qb64: m1.qb64 });

      expect(m2.code).toBe(MtrDex.Ed25519);
      expect(m2.raw).toEqual(raw);
      expect(m2.qb64).toBe(m1.qb64);
    });

    it('recovers code and raw from Ed25519_Sig qb64', () => {
      const raw = new Uint8Array(64);
      crypto.getRandomValues(raw);

      const m1 = new Matter({ code: MtrDex.Ed25519_Sig, raw });
      const m2 = new Matter({ qb64: m1.qb64 });

      expect(m2.code).toBe(MtrDex.Ed25519_Sig);
      expect(m2.raw).toEqual(raw);
    });

    it('recovers code and raw from ECDSA_256k1_Ver qb64 (4-char code)', () => {
      const raw = new Uint8Array(33);
      crypto.getRandomValues(raw);

      const m1 = new Matter({ code: MtrDex.ECDSA_256k1_Ver, raw });
      const m2 = new Matter({ qb64: m1.qb64 });

      expect(m2.code).toBe(MtrDex.ECDSA_256k1_Ver);
      expect(m2.raw).toEqual(raw);
    });
  });

  describe('round-trip for all codes in MtrSizage', () => {
    for (const [code, sizage] of Object.entries(MtrSizage)) {
      it(`round-trips code "${code}" (fs=${sizage.fs})`, () => {
        const rawLen = rawSizeForCode(code);
        const raw = new Uint8Array(rawLen);
        crypto.getRandomValues(raw);

        const m1 = new Matter({ code, raw });
        expect(m1.qb64).toHaveLength(sizage.fs);
        expect(m1.code).toBe(code);

        const m2 = new Matter({ qb64: m1.qb64 });
        expect(m2.code).toBe(code);
        expect(m2.raw).toEqual(raw);
        expect(m2.qb64).toBe(m1.qb64);
      });
    }
  });

  describe('validation', () => {
    it('rejects wrong raw size for code', () => {
      // Ed25519 expects 32 bytes, pass 16
      const wrongRaw = new Uint8Array(16);
      expect(() => new Matter({ code: MtrDex.Ed25519, raw: wrongRaw })).toThrow();
    });

    it('rejects unknown code', () => {
      const raw = new Uint8Array(32);
      expect(() => new Matter({ code: 'ZZ', raw })).toThrow();
    });

    it('rejects empty qb64', () => {
      expect(() => new Matter({ qb64: '' })).toThrow();
    });

    it('rejects qb64 with unknown code', () => {
      expect(() => new Matter({ qb64: '9999' })).toThrow();
    });
  });

  describe('property-based: encode/decode idempotence', () => {
    it('encode(decode(encode(code, raw))) is idempotent', () => {
      // Pick a code at random from the table, generate matching raw bytes
      const codes = Object.keys(MtrSizage);

      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: codes.length - 1 }),
          fc.infiniteStream(fc.integer({ min: 0, max: 255 })),
          (codeIdx, byteStream) => {
            const code = codes[codeIdx];
            const rawLen = rawSizeForCode(code);
            const raw = new Uint8Array(rawLen);
            const iter = byteStream[Symbol.iterator]();
            for (let i = 0; i < rawLen; i++) {
              raw[i] = iter.next().value!;
            }

            // encode
            const m1 = new Matter({ code, raw });
            const qb64 = m1.qb64;

            // decode
            const m2 = new Matter({ qb64 });

            // re-encode
            const m3 = new Matter({ code: m2.code, raw: m2.raw });

            expect(m3.qb64).toBe(qb64);
            expect(m3.code).toBe(code);
            expect(m3.raw).toEqual(raw);
          },
        ),
        { numRuns: 200 },
      );
    });
  });

  describe('qb2 (binary domain)', () => {
    it('produces qb2 whose length is 3/4 of qb64 length', () => {
      const raw = new Uint8Array(32);
      crypto.getRandomValues(raw);
      const m = new Matter({ code: MtrDex.Ed25519, raw });

      // qb2 is the full B-domain representation (code + raw as bytes)
      expect(m.qb2.length).toBe((m.qb64.length * 3) / 4);
    });
  });
});
