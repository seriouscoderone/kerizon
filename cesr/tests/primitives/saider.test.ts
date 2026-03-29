import { describe, it, expect } from 'vitest';
import { Saider } from '../../src/primitives/saider.js';

describe('Saider', () => {
  describe('saidify()', () => {
    it('produces a deterministic SAID for a simple object', () => {
      const fields = { d: '', v: 'KERI10JSON000000_', t: 'icp', i: '' };
      const result = Saider.saidify(fields);
      expect(result.d).toBeTypeOf('string');
      expect((result.d as string).length).toBe(44); // Blake3-256 qb64 is 44 chars
      expect((result.d as string)[0]).toBe('E'); // Blake3-256 code prefix
    });

    it('is deterministic — same input yields same SAID', () => {
      const fields = { d: '', name: 'test', value: 42 };
      const r1 = Saider.saidify(fields);
      const r2 = Saider.saidify(fields);
      expect(r1.d).toBe(r2.d);
    });

    it('uses custom label', () => {
      const fields = { id: '', name: 'custom' };
      const result = Saider.saidify(fields, 'id');
      expect(result.id).toBeTypeOf('string');
      expect((result.id as string).length).toBe(44);
    });

    it('sets both d and i for inception events (t=icp)', () => {
      const fields = { d: '', i: '', v: 'KERI10JSON000000_', t: 'icp', s: '0', kt: '1', k: [], nt: '1', n: [], bt: '0', b: [], c: [], a: [] };
      const result = Saider.saidify(fields);
      expect(result.d).toBe(result.i);
      expect((result.d as string).length).toBe(44);
    });

    it('sets both d and i for delegated inception events (t=dip)', () => {
      const fields = { d: '', i: '', v: 'KERI10JSON000000_', t: 'dip', s: '0', kt: '1', k: [], nt: '1', n: [], bt: '0', b: [], c: [], a: [], di: 'E1234' };
      const result = Saider.saidify(fields);
      expect(result.d).toBe(result.i);
    });

    it('does not overwrite i for non-inception events', () => {
      const fields = { d: '', i: 'Eexisting', v: 'KERI10JSON000000_', t: 'rot', s: '1' };
      const result = Saider.saidify(fields);
      expect(result.i).toBe('Eexisting');
      expect(result.d).not.toBe(result.i);
    });
  });

  describe('verify()', () => {
    it('returns true for correctly saidified fields', () => {
      const fields = { d: '', msg: 'hello world' };
      const saidified = Saider.saidify(fields);
      expect(Saider.verify(saidified)).toBe(true);
    });

    it('returns false after mutating a field', () => {
      const fields = { d: '', msg: 'hello world' };
      const saidified = Saider.saidify(fields);
      const mutated = { ...saidified, msg: 'tampered' };
      expect(Saider.verify(mutated)).toBe(false);
    });

    it('returns false after mutating the SAID itself', () => {
      const fields = { d: '', msg: 'hello world' };
      const saidified = Saider.saidify(fields);
      const mutated = { ...saidified, d: 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
      expect(Saider.verify(mutated)).toBe(false);
    });

    it('verifies with custom label', () => {
      const fields = { id: '', data: [1, 2, 3] };
      const saidified = Saider.saidify(fields, 'id');
      expect(Saider.verify(saidified, 'id')).toBe(true);
    });

    it('verifies inception d==i', () => {
      const fields = { d: '', i: '', v: 'KERI10JSON000000_', t: 'icp', s: '0', kt: '1', k: [], nt: '1', n: [], bt: '0', b: [], c: [], a: [] };
      const saidified = Saider.saidify(fields);
      expect(Saider.verify(saidified)).toBe(true);
    });
  });
});
