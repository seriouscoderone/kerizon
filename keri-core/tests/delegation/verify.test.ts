import { describe, it, expect } from 'vitest';
import { verifyDelegationSeal, findDelegationSeal } from '../../src/delegation/verify.js';
import type { DelegationSeal } from '../../src/delegation/types.js';

describe('verifyDelegationSeal', () => {
  const seal: DelegationSeal = {
    i: 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc',
    s: '0',
    d: 'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj',
  };

  it('returns true when all fields match', () => {
    expect(
      verifyDelegationSeal(seal, seal.i, 0, seal.d),
    ).toBe(true);
  });

  it('returns false on prefix mismatch', () => {
    expect(
      verifyDelegationSeal(seal, 'Ewrong_prefix_000000000000000000000000000000', 0, seal.d),
    ).toBe(false);
  });

  it('returns false on sn mismatch', () => {
    expect(
      verifyDelegationSeal(seal, seal.i, 1, seal.d),
    ).toBe(false);
  });

  it('returns false on SAID mismatch', () => {
    expect(
      verifyDelegationSeal(seal, seal.i, 0, 'Ewrong_said_0000000000000000000000000000000'),
    ).toBe(false);
  });
});

describe('findDelegationSeal', () => {
  const targetPrefix = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';
  const targetSn = 0;
  const targetSaid = 'EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj';

  const matchingSeal = { i: targetPrefix, s: '0', d: targetSaid };
  const unrelatedSeal = { i: 'Eother_prefix_00000000000000000000000000000000', s: '1', d: 'Eother_said_000000000000000000000000000000000' };

  const delegatorEvents: Record<string, unknown>[] = [
    { t: 'ixn', i: 'Edelegator', s: '1', a: [unrelatedSeal] },
    { t: 'ixn', i: 'Edelegator', s: '2', a: [matchingSeal] },
  ];

  it('finds matching seal in event anchors', () => {
    const result = findDelegationSeal(delegatorEvents, targetPrefix, targetSn, targetSaid);
    expect(result).toEqual(matchingSeal);
  });

  it('returns null when no match', () => {
    const events: Record<string, unknown>[] = [
      { t: 'ixn', i: 'Edelegator', s: '1', a: [unrelatedSeal] },
    ];
    const result = findDelegationSeal(events, targetPrefix, targetSn, targetSaid);
    expect(result).toBeNull();
  });
});
