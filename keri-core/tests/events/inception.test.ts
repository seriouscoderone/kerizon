import { describe, it, expect } from 'vitest';
import { incept } from '../../src/events/inception.js';
import { ICP_FIELDS, DIP_FIELDS } from '../../src/events/types.js';

describe('incept', () => {
  const keys = ['DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'];
  const nextDigests = ['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj'];

  it('creates an inception event with correct field order', () => {
    const serder = incept({ keys, nextDigests });
    const fieldOrder = Object.keys(serder.ked);
    const expected = [...ICP_FIELDS];
    expect(fieldOrder).toEqual(expected);
  });

  it('has a valid SAID', () => {
    const serder = incept({ keys, nextDigests });
    expect(serder.verifySaid()).toBe(true);
  });

  it('for non-delegated inception: i === d', () => {
    const serder = incept({ keys, nextDigests });
    expect(serder.ked['i']).toBe(serder.ked['d']);
  });

  it('has sn === 0', () => {
    const serder = incept({ keys, nextDigests });
    expect(serder.sn).toBe(0);
    expect(serder.ked['s']).toBe('0');
  });

  it('keys match config', () => {
    const serder = incept({ keys, nextDigests });
    expect(serder.ked['k']).toEqual(keys);
  });

  it('event type is icp', () => {
    const serder = incept({ keys, nextDigests });
    expect(serder.ilk).toBe('icp');
  });

  it('sets default thresholds to "1"', () => {
    const serder = incept({ keys, nextDigests });
    expect(serder.ked['kt']).toBe('1');
    expect(serder.ked['nt']).toBe('1');
  });

  it('sets witness threshold as hex', () => {
    const serder = incept({ keys, nextDigests, witnessThreshold: 2 });
    expect(serder.ked['bt']).toBe('2');
  });

  it('uses custom signing threshold', () => {
    const serder = incept({ keys, nextDigests, signingThreshold: '2' });
    expect(serder.ked['kt']).toBe('2');
  });

  it('includes witnesses when provided', () => {
    const witnesses = ['BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha'];
    const serder = incept({ keys, nextDigests, witnesses, witnessThreshold: 1 });
    expect(serder.ked['b']).toEqual(witnesses);
    expect(serder.ked['bt']).toBe('1');
  });

  it('includes config traits when provided', () => {
    const serder = incept({ keys, nextDigests, configTraits: ['EO'] });
    expect(serder.ked['c']).toEqual(['EO']);
  });

  it('includes data when provided', () => {
    const data = [{ test: 'value' }];
    const serder = incept({ keys, nextDigests, data });
    expect(serder.ked['a']).toEqual(data);
  });

  describe('delegated inception (dip)', () => {
    const delegator = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';

    it('creates a dip event when delegator is present', () => {
      const serder = incept({ keys, nextDigests, delegator });
      expect(serder.ilk).toBe('dip');
    });

    it('has correct field order for dip', () => {
      const serder = incept({ keys, nextDigests, delegator });
      const fieldOrder = Object.keys(serder.ked);
      expect(fieldOrder).toEqual([...DIP_FIELDS]);
    });

    it('has a valid SAID', () => {
      const serder = incept({ keys, nextDigests, delegator });
      expect(serder.verifySaid()).toBe(true);
    });

    it('for delegated inception: i === d', () => {
      const serder = incept({ keys, nextDigests, delegator });
      expect(serder.ked['i']).toBe(serder.ked['d']);
    });

    it('includes di field with delegator prefix', () => {
      const serder = incept({ keys, nextDigests, delegator });
      expect(serder.ked['di']).toBe(delegator);
    });
  });
});
