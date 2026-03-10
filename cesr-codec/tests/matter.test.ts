import { describe, test, expect } from 'vitest';
import { Matter, parseMatterFromText } from '../src/matter.js';
import { base64urlEncode, padSize } from '../src/codec.js';

describe('Matter class', () => {
  test('construct from code + raw and read qb64', () => {
    const raw = new Uint8Array(32).fill(0x42);
    const matter = new Matter({ code: 'D', raw });
    expect(matter.code).toBe('D');
    expect(matter.raw).toEqual(raw);
    const qb64 = matter.qb64;
    expect(qb64[0]).toBe('D');
    expect(qb64.length).toBe(44); // 1 code + 43 body chars
  });

  test('construct from qb64 round-trips', () => {
    const raw = new Uint8Array(32).fill(0xAB);
    const m1 = new Matter({ code: 'D', raw });
    const m2 = new Matter({ qb64: m1.qb64 });
    expect(m2.code).toBe('D');
    expect(m2.raw).toEqual(raw);
    expect(m2.qb64).toBe(m1.qb64);
  });

  test('construct from qb64b round-trips', () => {
    const raw = new Uint8Array(32).fill(0xCD);
    const m1 = new Matter({ code: 'D', raw });
    const m2 = new Matter({ qb64b: m1.qb64b });
    expect(m2.code).toBe('D');
    expect(m2.raw).toEqual(raw);
  });

  test('qb2 is base64url decode of qb64', () => {
    const raw = new Uint8Array(32).fill(0x11);
    const matter = new Matter({ code: 'D', raw });
    expect(matter.qb2.length).toBe(33); // 32 raw + 1 pad byte
  });

  test('fullSize matches expected text size', () => {
    const raw32 = new Uint8Array(32).fill(0);
    expect(new Matter({ code: 'D', raw: raw32 }).fullSize).toBe(44);

    const raw64 = new Uint8Array(64).fill(0);
    expect(new Matter({ code: '0B', raw: raw64 }).fullSize).toBe(88);

    const raw16 = new Uint8Array(16).fill(0);
    expect(new Matter({ code: '0A', raw: raw16 }).fullSize).toBe(24);
  });

  test('instanceof check works', () => {
    const m = new Matter({ code: 'D', raw: new Uint8Array(32) });
    expect(m instanceof Matter).toBe(true);
  });

  test('throws on unknown matter code', () => {
    expect(() => new Matter({ code: 'Z', raw: new Uint8Array(32) })).toThrow('Unknown matter code');
  });

  test('throws on indexed code used as matter', () => {
    // A is an indexed-signature code, not a matter code
    expect(() => new Matter({ code: 'A', raw: new Uint8Array(64) })).toThrow('Unknown matter code');
  });

  test('throws on wrong raw size', () => {
    expect(() => new Matter({ code: 'D', raw: new Uint8Array(16) })).toThrow('Raw size');
  });

  test('parseMatterFromText works', () => {
    const raw = new Uint8Array(32).fill(0x77);
    const m1 = new Matter({ code: 'D', raw });
    const encoded = new TextEncoder().encode(m1.qb64);
    const m2 = parseMatterFromText(encoded);
    expect(m2.code).toBe('D');
    expect(m2.raw).toEqual(raw);
    expect(m2 instanceof Matter).toBe(true);
  });

  test('all matter codes round-trip', () => {
    const matterCodes = [
      { code: 'D', rawSize: 32 },
      { code: 'E', rawSize: 32 },
      { code: 'F', rawSize: 32 },
      { code: 'G', rawSize: 32 },
      { code: 'H', rawSize: 32 },
      { code: 'I', rawSize: 32 },
      { code: 'J', rawSize: 32 },
      { code: 'K', rawSize: 57 },
      { code: 'L', rawSize: 32 },
      { code: '0A', rawSize: 16 },
      { code: '0B', rawSize: 64 },
      { code: '0C', rawSize: 24 },
      { code: '0D', rawSize: 64 },
      { code: '0E', rawSize: 64 },
      { code: '0F', rawSize: 64 },
      { code: '0G', rawSize: 64 },
    ];

    for (const { code, rawSize } of matterCodes) {
      const raw = new Uint8Array(rawSize).fill(0x42);
      // Zero constrained lead bits for K and 0C
      const ps = padSize(code, rawSize);
      const cs = code.length;
      if (cs > ps) {
        const lcb = (cs - ps) * 6;
        const fullBytes = Math.floor(lcb / 8);
        const remainingBits = lcb % 8;
        for (let i = 0; i < fullBytes; i++) raw[i] = 0;
        if (remainingBits > 0) {
          raw[fullBytes] &= (1 << (8 - remainingBits)) - 1;
        }
      }
      const m1 = new Matter({ code, raw });
      const m2 = new Matter({ qb64: m1.qb64 });
      expect(m2.code).toBe(code);
      expect(m2.raw).toEqual(raw);
    }
  });
});
