import { describe, it, expect } from 'vitest';
import { rotate } from '../../src/events/rotation.js';
import { ROT_FIELDS } from '../../src/events/types.js';

describe('rotate', () => {
  const prefix = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
  const priorDigest = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
  const keys = ['DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'];
  const nextDigests = ['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj'];

  it('has correct field order', () => {
    const serder = rotate({ prefix, priorDigest, sn: 1, keys, nextDigests });
    const fieldOrder = Object.keys(serder.ked);
    expect(fieldOrder).toEqual([...ROT_FIELDS]);
  });

  it('has a valid SAID', () => {
    const serder = rotate({ prefix, priorDigest, sn: 1, keys, nextDigests });
    expect(serder.verifySaid()).toBe(true);
  });

  it('sn matches config', () => {
    const serder = rotate({ prefix, priorDigest, sn: 3, keys, nextDigests });
    expect(serder.sn).toBe(3);
    expect(serder.ked['s']).toBe('3');
  });

  it('sn encodes as hex', () => {
    const serder = rotate({ prefix, priorDigest, sn: 255, keys, nextDigests });
    expect(serder.ked['s']).toBe('ff');
  });

  it('p matches config.priorDigest', () => {
    const serder = rotate({ prefix, priorDigest, sn: 1, keys, nextDigests });
    expect(serder.ked['p']).toBe(priorDigest);
  });

  it('event type is rot', () => {
    const serder = rotate({ prefix, priorDigest, sn: 1, keys, nextDigests });
    expect(serder.ilk).toBe('rot');
  });

  it('prefix is set in i field', () => {
    const serder = rotate({ prefix, priorDigest, sn: 1, keys, nextDigests });
    expect(serder.ked['i']).toBe(prefix);
  });

  it('for rotation: d !== i', () => {
    const serder = rotate({ prefix, priorDigest, sn: 1, keys, nextDigests });
    expect(serder.ked['d']).not.toBe(serder.ked['i']);
  });

  it('includes witness changes when provided', () => {
    const witnessesToAdd = ['BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha'];
    const witnessesToRemove = ['BDno0sIUL6MRCEWyc7Y2o8Hx4HCJ20EEq1eaeXB43xe6'];
    const serder = rotate({
      prefix, priorDigest, sn: 1, keys, nextDigests,
      witnessesToAdd, witnessesToRemove,
    });
    expect(serder.ked['ba']).toEqual(witnessesToAdd);
    expect(serder.ked['br']).toEqual(witnessesToRemove);
  });

  it('defaults witness lists to empty arrays', () => {
    const serder = rotate({ prefix, priorDigest, sn: 1, keys, nextDigests });
    expect(serder.ked['ba']).toEqual([]);
    expect(serder.ked['br']).toEqual([]);
  });

  it('includes data when provided', () => {
    const data = [{ anchor: 'value' }];
    const serder = rotate({ prefix, priorDigest, sn: 1, keys, nextDigests, data });
    expect(serder.ked['a']).toEqual(data);
  });
});
