import { describe, it, expect } from 'vitest';
import { detectFork, isForked } from '../../src/evidence/detect.js';

describe('detectFork', () => {
  const aid = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';

  it('detects conflicting events at same (aid, sn)', () => {
    const accepted = { aid, sn: 3, said: 'ESAID_accepted________________________________' };
    const incoming = { aid, sn: 3, said: 'ESAID_incoming________________________________' };

    const fork = detectFork(accepted, incoming);
    expect(fork).not.toBeNull();
    expect(fork!.aid).toBe(aid);
    expect(fork!.sn).toBe(3);
    expect(fork!.firstSeenSaid).toBe('ESAID_accepted________________________________');
    expect(fork!.conflictingSaid).toBe('ESAID_incoming________________________________');
  });

  it('returns null for duplicate (same said)', () => {
    const said = 'ESAID_same____________________________________';
    const accepted = { aid, sn: 3, said };
    const incoming = { aid, sn: 3, said };

    expect(detectFork(accepted, incoming)).toBeNull();
  });

  it('returns null for different sn', () => {
    const accepted = { aid, sn: 3, said: 'ESAID_a_______________________________________' };
    const incoming = { aid, sn: 4, said: 'ESAID_b_______________________________________' };

    expect(detectFork(accepted, incoming)).toBeNull();
  });

  it('returns null for different aid', () => {
    const other = 'EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg';
    const accepted = { aid, sn: 3, said: 'ESAID_a_______________________________________' };
    const incoming = { aid: other, sn: 3, said: 'ESAID_b_______________________________________' };

    expect(detectFork(accepted, incoming)).toBeNull();
  });
});

describe('isForked', () => {
  const aid = 'ECtWlHS2Wbx5M2Rg6nm69PCtzwb1veiRNvDpBGF9Z1Pc';

  it('is symmetric', () => {
    const a = { aid, sn: 3, said: 'ESAID_a_______________________________________' };
    const b = { aid, sn: 3, said: 'ESAID_b_______________________________________' };

    expect(isForked(a, b)).toBe(true);
    expect(isForked(b, a)).toBe(true);
  });

  it('returns false for same said', () => {
    const said = 'ESAID_same____________________________________';
    const a = { aid, sn: 3, said };
    const b = { aid, sn: 3, said };

    expect(isForked(a, b)).toBe(false);
  });
});
