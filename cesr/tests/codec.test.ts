import { describe, it, expect } from 'vitest';
import { encode, decode, sniff } from '../src/codec.js';

describe('encode', () => {
  it('encodes Ed25519 verkey (code "D", 32 zero bytes) to 44-char qb64 starting with "D"', () => {
    const raw = new Uint8Array(32);
    const qb64 = encode('D', raw);
    expect(qb64).toHaveLength(44);
    expect(qb64[0]).toBe('D');
  });
});

describe('decode', () => {
  it('recovers code and raw from qb64', () => {
    const raw = new Uint8Array(32);
    raw[0] = 0xab;
    raw[31] = 0xcd;
    const qb64 = encode('D', raw);

    const result = decode(qb64);
    expect(result.code).toBe('D');
    expect(result.raw).toEqual(raw);
  });
});

describe('round-trip', () => {
  it('decode(encode(code, raw)) recovers original for Ed25519_Sig ("0B", 64 bytes)', () => {
    const raw = new Uint8Array(64);
    for (let i = 0; i < 64; i++) raw[i] = i;

    const qb64 = encode('0B', raw);
    const result = decode(qb64);

    expect(result.code).toBe('0B');
    expect(result.raw).toEqual(raw);
  });
});

describe('sniff', () => {
  it('detects JSON ("{" = 0x7b, tritet=3)', () => {
    expect(sniff(new Uint8Array([0x7b]))).toBe('JSON');
  });

  it('detects CBOR (0xa2, tritet=5)', () => {
    expect(sniff(new Uint8Array([0xa2]))).toBe('CBOR');
  });

  it('detects MGPK FixMap (0x82, tritet=4)', () => {
    expect(sniff(new Uint8Array([0x82]))).toBe('MGPK');
  });

  it('detects CESR ("-" = 0x2d, tritet=1)', () => {
    expect(sniff(new Uint8Array([0x2d]))).toBe('CESR');
  });

  it('returns null for empty input', () => {
    expect(sniff(new Uint8Array([]))).toBeNull();
  });
});
