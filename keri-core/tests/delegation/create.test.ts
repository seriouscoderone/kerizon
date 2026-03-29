import { describe, it, expect } from 'vitest';
import { createDelegatedInception, createDelegationSeal } from '../../src/delegation/create.js';
import { DIP_FIELDS } from '../../src/events/types.js';

describe('createDelegatedInception', () => {
  const delegatorAid = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
  const keys = ['DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA'];
  const nextDigests = ['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj'];

  it('dip event has t: "dip" and di field matching delegator', () => {
    const serder = createDelegatedInception({ delegatorAid, keys, nextDigests });
    expect(serder.ked['t']).toBe('dip');
    expect(serder.ked['di']).toBe(delegatorAid);
  });

  it('dip has i === d (inception SAID)', () => {
    const serder = createDelegatedInception({ delegatorAid, keys, nextDigests });
    expect(serder.ked['i']).toBe(serder.ked['d']);
  });

  it('dip has sn === 0', () => {
    const serder = createDelegatedInception({ delegatorAid, keys, nextDigests });
    expect(serder.ked['s']).toBe('0');
  });

  it('dip SAID verifies', () => {
    const serder = createDelegatedInception({ delegatorAid, keys, nextDigests });
    expect(serder.verifySaid()).toBe(true);
  });

  it('has correct field order for dip', () => {
    const serder = createDelegatedInception({ delegatorAid, keys, nextDigests });
    const fieldOrder = Object.keys(serder.ked);
    expect(fieldOrder).toEqual([...DIP_FIELDS]);
  });
});

describe('createDelegationSeal', () => {
  it('produces { i, s, d }', () => {
    const seal = createDelegationSeal(
      'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
      0,
      'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj',
    );
    expect(seal).toHaveProperty('i');
    expect(seal).toHaveProperty('s');
    expect(seal).toHaveProperty('d');
  });

  it('s field is hex-encoded', () => {
    const seal = createDelegationSeal(
      'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
      255,
      'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj',
    );
    expect(seal.s).toBe('ff');
  });
});
