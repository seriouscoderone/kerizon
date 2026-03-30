import { describe, it, expect } from 'vitest';
import {
  computeBlid,
  deriveUuid,
  verifyBlid,
} from '../../src/privacy/blinding.js';

describe('computeBlid', () => {
  it('is deterministic — same salt+sn produces same BLID', () => {
    const a = computeBlid('secret-salt', 0);
    const b = computeBlid('secret-salt', 0);
    expect(a).toBe(b);
  });

  it('different sn produces different BLID', () => {
    const a = computeBlid('secret-salt', 0);
    const b = computeBlid('secret-salt', 1);
    expect(a).not.toBe(b);
  });
});

describe('verifyBlid', () => {
  it('returns true for matching salt+sn', () => {
    const blid = computeBlid('my-salt', 42);
    expect(verifyBlid(blid, 'my-salt', 42)).toBe(true);
  });

  it('returns false for wrong sn', () => {
    const blid = computeBlid('my-salt', 42);
    expect(verifyBlid(blid, 'my-salt', 99)).toBe(false);
  });
});

describe('deriveUuid', () => {
  it('is deterministic and unique per index', () => {
    const a = deriveUuid('salt', 0);
    const b = deriveUuid('salt', 0);
    const c = deriveUuid('salt', 1);

    expect(a).toBe(b); // deterministic
    expect(a).not.toBe(c); // unique per index
  });
});
