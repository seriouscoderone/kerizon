import { describe, it, expect } from 'vitest';
import { makeVersionString, parseVersionString } from '../../src/composition/version-string.js';

describe('VersionString', () => {
  describe('makeVersionString()', () => {
    it('generates v1 format matching /^KERI10JSON[0-9a-f]{6}_$/', () => {
      const vs = makeVersionString({
        protocol: 'KERI',
        major: 1,
        minor: 0,
        kind: 'JSON',
        size: 256,
      });
      expect(vs).toMatch(/^KERI10JSON[0-9a-f]{6}_$/);
    });

    it('produces a string of exactly 17 chars', () => {
      const vs = makeVersionString({
        protocol: 'KERI',
        major: 1,
        minor: 0,
        kind: 'JSON',
        size: 0,
      });
      expect(vs.length).toBe(17);
    });

    it('encodes size as 6-digit zero-padded hex', () => {
      const vs = makeVersionString({
        protocol: 'KERI',
        major: 1,
        minor: 0,
        kind: 'JSON',
        size: 255,
      });
      // 255 = 0xff → "0000ff"
      expect(vs).toBe('KERI10JSON0000ff_');
    });

    it('encodes version digits correctly', () => {
      const vs = makeVersionString({
        protocol: 'KERI',
        major: 2,
        minor: 1,
        kind: 'JSON',
        size: 0,
      });
      expect(vs).toBe('KERI21JSON000000_');
    });
  });

  describe('parseVersionString()', () => {
    it('parses a v1 version string correctly', () => {
      const info = parseVersionString('KERI10JSON0000ff_');
      expect(info.protocol).toBe('KERI');
      expect(info.major).toBe(1);
      expect(info.minor).toBe(0);
      expect(info.kind).toBe('JSON');
      expect(info.size).toBe(255);
    });

    it('round-trips size through make → parse', () => {
      for (const size of [0, 1, 100, 4096, 16777215]) {
        const vs = makeVersionString({
          protocol: 'KERI',
          major: 1,
          minor: 0,
          kind: 'JSON',
          size,
        });
        const parsed = parseVersionString(vs);
        expect(parsed.size).toBe(size);
      }
    });

    it('round-trips protocol/version/kind through make → parse', () => {
      const info = {
        protocol: 'ACDC',
        major: 1,
        minor: 0,
        kind: 'CBOR',
        size: 42,
      };
      const vs = makeVersionString(info);
      const parsed = parseVersionString(vs);
      expect(parsed.protocol).toBe('ACDC');
      expect(parsed.major).toBe(1);
      expect(parsed.minor).toBe(0);
      expect(parsed.kind).toBe('CBOR');
      expect(parsed.size).toBe(42);
    });

    it('throws on invalid length', () => {
      expect(() => parseVersionString('short')).toThrow();
    });

    it('throws on missing terminator', () => {
      expect(() => parseVersionString('KERI10JSON0000ffX')).toThrow();
    });
  });
});
