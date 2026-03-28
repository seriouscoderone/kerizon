import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  CODE_TABLE,
  encodePrimitive,
  decodePrimitive,
  type CesrPrimitive,
} from '../../src/util/cesr-codec.js';
import { arbPrimitiveForCode } from '../../src/generators/cesr.js';

describe('CESR code table coverage', () => {
  const entries = Object.values(CODE_TABLE);

  it('all codes produce T-domain strings of correct length', () => {
    for (const entry of entries) {
      fc.assert(
        fc.property(
          arbPrimitiveForCode(entry.code),
          (primitive: CesrPrimitive) => {
            const encoded = encodePrimitive(primitive);
            return encoded.length === entry.fs;
          },
        ),
        { numRuns: 50 },
      );
    }
  });

  it('all codes start with their code prefix', () => {
    for (const entry of entries) {
      fc.assert(
        fc.property(
          arbPrimitiveForCode(entry.code),
          (primitive: CesrPrimitive) => {
            const encoded = encodePrimitive(primitive);
            return encoded.startsWith(entry.code);
          },
        ),
        { numRuns: 50 },
      );
    }
  });

  it('all codes round-trip through encode/decode', () => {
    for (const entry of entries) {
      fc.assert(
        fc.property(
          arbPrimitiveForCode(entry.code),
          (primitive: CesrPrimitive) => {
            const encoded = encodePrimitive(primitive);
            const { primitive: decoded, consumed } = decodePrimitive(encoded);
            return (
              consumed === entry.fs &&
              decoded.entry.code === entry.code &&
              decoded.raw.length === entry.rawSize
            );
          },
        ),
        { numRuns: 50 },
      );
    }
  });

  it('T-domain size is always a multiple of 4 (24-bit alignment)', () => {
    for (const entry of entries) {
      expect(entry.fs % 4).toBe(0);
    }
  });

  it('raw size is consistent with T-domain size', () => {
    for (const entry of entries) {
      // Total T-domain chars = hs + ss + rawB64Chars
      // rawB64Chars encodes (rawSize + pad) bytes, where pad aligns to 3-byte boundary
      const rawB64Chars = entry.fs - entry.hs - entry.ss;
      const totalRawBytes = (rawB64Chars * 3) / 4;
      expect(totalRawBytes).toBeGreaterThanOrEqual(entry.rawSize);
      // Pad should be 0, 1, or 2 bytes
      const pad = totalRawBytes - entry.rawSize;
      expect(pad).toBeGreaterThanOrEqual(0);
      expect(pad).toBeLessThanOrEqual(2);
    }
  });
});
