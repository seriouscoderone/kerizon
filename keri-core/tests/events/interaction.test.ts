import { describe, it, expect } from 'vitest';
import { interact } from '../../src/events/interaction.js';
import { IXN_FIELDS } from '../../src/events/types.js';

describe('interact', () => {
  const prefix = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
  const priorDigest = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';

  it('has correct field order', () => {
    const serder = interact({ prefix, priorDigest, sn: 1 });
    const fieldOrder = Object.keys(serder.ked);
    expect(fieldOrder).toEqual([...IXN_FIELDS]);
  });

  it('has a valid SAID', () => {
    const serder = interact({ prefix, priorDigest, sn: 1 });
    expect(serder.verifySaid()).toBe(true);
  });

  it('sn matches config', () => {
    const serder = interact({ prefix, priorDigest, sn: 5 });
    expect(serder.sn).toBe(5);
    expect(serder.ked['s']).toBe('5');
  });

  it('sn encodes as hex', () => {
    const serder = interact({ prefix, priorDigest, sn: 16 });
    expect(serder.ked['s']).toBe('10');
  });

  it('data preserved in a field', () => {
    const data = [{ digest: 'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj' }];
    const serder = interact({ prefix, priorDigest, sn: 1, data });
    expect(serder.ked['a']).toEqual(data);
  });

  it('data defaults to empty array', () => {
    const serder = interact({ prefix, priorDigest, sn: 1 });
    expect(serder.ked['a']).toEqual([]);
  });

  it('event type is ixn', () => {
    const serder = interact({ prefix, priorDigest, sn: 1 });
    expect(serder.ilk).toBe('ixn');
  });

  it('prefix is set in i field', () => {
    const serder = interact({ prefix, priorDigest, sn: 1 });
    expect(serder.ked['i']).toBe(prefix);
  });

  it('p matches config.priorDigest', () => {
    const serder = interact({ prefix, priorDigest, sn: 1 });
    expect(serder.ked['p']).toBe(priorDigest);
  });

  it('for interaction: d !== i', () => {
    const serder = interact({ prefix, priorDigest, sn: 1 });
    expect(serder.ked['d']).not.toBe(serder.ked['i']);
  });
});
