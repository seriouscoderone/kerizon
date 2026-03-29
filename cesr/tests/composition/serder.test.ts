import { describe, it, expect } from 'vitest';
import { Serder } from '../../src/composition/serder.js';

describe('Serder', () => {
  const icpFields: Record<string, unknown> = {
    v: '',
    t: 'icp',
    d: '',
    i: '',
    s: '0',
    kt: '1',
    k: ['DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'],
    nt: '1',
    n: ['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj'],
    bt: '0',
    b: [],
    c: [],
    a: [],
  };

  const ixnFields: Record<string, unknown> = {
    v: '',
    t: 'ixn',
    d: '',
    i: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
    s: '1',
    p: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
    a: [],
  };

  describe('fromKed()', () => {
    it('creates from KED with auto-SAID and version string', () => {
      const serder = Serder.fromKed(icpFields);
      expect(serder.ked.v).toMatch(/^KERI10JSON[0-9a-f]{6}_$/);
      expect(serder.ked.d).toBeTypeOf('string');
      expect((serder.ked.d as string).length).toBe(44);
    });

    it('SAID starts with E (Blake3-256)', () => {
      const serder = Serder.fromKed(icpFields);
      expect((serder.ked.d as string)[0]).toBe('E');
    });

    it('for inception: ked.i === ked.d', () => {
      const serder = Serder.fromKed(icpFields);
      expect(serder.ked.i).toBe(serder.ked.d);
    });

    it('for non-inception (ixn): ked.i is the provided prefix, ked.d is the SAID', () => {
      const serder = Serder.fromKed(ixnFields);
      expect(serder.ked.i).toBe('ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc');
      expect(serder.ked.d).not.toBe(serder.ked.i);
      expect((serder.ked.d as string)[0]).toBe('E');
    });

    it('verifySaid() returns true', () => {
      const serder = Serder.fromKed(icpFields);
      expect(serder.verifySaid()).toBe(true);
    });

    it('verifySaid() returns true for ixn', () => {
      const serder = Serder.fromKed(ixnFields);
      expect(serder.verifySaid()).toBe(true);
    });

    it('raw matches JSON.stringify(ked) as bytes', () => {
      const serder = Serder.fromKed(icpFields);
      const expected = new TextEncoder().encode(JSON.stringify(serder.ked));
      expect(serder.raw).toEqual(expected);
    });

    it('said property equals ked.d', () => {
      const serder = Serder.fromKed(icpFields);
      expect(serder.said).toBe(serder.ked.d);
    });
  });

  describe('fromRaw()', () => {
    it('deserializes raw bytes back to matching Serder', () => {
      const original = Serder.fromKed(icpFields);
      const restored = Serder.fromRaw(original.raw);
      expect(restored.ked).toEqual(original.ked);
      expect(restored.said).toBe(original.said);
    });

    it('verifySaid() returns true for deserialized Serder', () => {
      const original = Serder.fromKed(ixnFields);
      const restored = Serder.fromRaw(original.raw);
      expect(restored.verifySaid()).toBe(true);
    });
  });

  describe('accessors', () => {
    it('ilk returns the event type', () => {
      const serder = Serder.fromKed(icpFields);
      expect(serder.ilk).toBe('icp');
    });

    it('pre returns the AID prefix', () => {
      const serder = Serder.fromKed(ixnFields);
      expect(serder.pre).toBe('ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc');
    });

    it('pre returns the SAID for inception events', () => {
      const serder = Serder.fromKed(icpFields);
      expect(serder.pre).toBe(serder.said);
    });

    it('sn returns the sequence number parsed from hex', () => {
      const serder = Serder.fromKed(icpFields);
      expect(serder.sn).toBe(0);

      const ixnSerder = Serder.fromKed(ixnFields);
      expect(ixnSerder.sn).toBe(1);
    });

    it('sn handles hex-encoded sequence numbers', () => {
      const fields = { ...ixnFields, s: 'a' };
      const serder = Serder.fromKed(fields);
      expect(serder.sn).toBe(10);
    });
  });

  describe('version string in ked', () => {
    it('version string size matches raw byte length', () => {
      const serder = Serder.fromKed(icpFields);
      const vs = serder.ked.v as string;
      // Extract size from the version string (6 hex digits before _)
      const sizeHex = vs.slice(10, 16);
      const size = parseInt(sizeHex, 16);
      expect(size).toBe(serder.raw.length);
    });
  });
});
