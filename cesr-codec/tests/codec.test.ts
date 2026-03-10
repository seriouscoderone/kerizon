import { describe, test, expect } from 'vitest';
import {
  CODE_TABLE,
  leadConstrainedBits,
  base64urlEncode, base64urlDecode,
  TFromR, BFromR, RFromT, RFromB,
  type CodeEntry,
} from '../src/codec.js';

function validRawForEntry(entry: CodeEntry, fillByte: number): Uint8Array {
  const raw = new Uint8Array(entry.rawSize).fill(fillByte);
  const lcb = leadConstrainedBits(entry.code, entry.rawSize);
  if (lcb > 0) {
    const fullBytes = Math.floor(lcb / 8);
    const remainingBits = lcb % 8;
    for (let i = 0; i < fullBytes; i++) raw[i] = 0;
    if (remainingBits > 0) {
      raw[fullBytes] &= (1 << (8 - remainingBits)) - 1;
    }
  }
  return raw;
}

describe('CESR Codec Library', () => {

  test('text round-trip for all codes', () => {
    for (const entry of CODE_TABLE) {
      const raw = validRawForEntry(entry, 42);
      const text = TFromR(entry.code, raw);
      const result = RFromT(text);
      expect(result.code).toBe(entry.code);
      expect(result.raw).toEqual(raw);
    }
  });

  test('binary round-trip for all codes', () => {
    for (const entry of CODE_TABLE) {
      const raw = validRawForEntry(entry, 42);
      const bin = BFromR(entry.code, raw);
      const result = RFromB(bin);
      expect(result.code).toBe(entry.code);
      expect(result.raw).toEqual(raw);
    }
  });

  test('code extraction with arbitrary raw', () => {
    for (const entry of CODE_TABLE) {
      const raw = new Uint8Array(entry.rawSize).fill(255);
      const text = TFromR(entry.code, raw);
      const result = RFromT(text);
      expect(result.code).toBe(entry.code);
    }
  });

  test('parse equivalence: text and binary parse same raw', () => {
    for (const entry of CODE_TABLE) {
      const raw = validRawForEntry(entry, 42);
      const text = TFromR(entry.code, raw);
      const resultT = RFromT(text);
      const resultB = RFromB(base64urlDecode(text));
      expect(resultT.raw).toEqual(resultB.raw);
    }
  });
});
