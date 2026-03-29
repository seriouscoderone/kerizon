import { describe, it, expect } from 'vitest';
import { Signer, Diger } from '@kerizon/cesr';
import { computeNextDigest, verifyPreRotation } from '../../src/key-commitment/pre-rotation.js';
import { isTransferable, isTransferableCode } from '../../src/key-commitment/transferability.js';

describe('computeNextDigest', () => {
  it('produces an E-prefixed 44-char string', async () => {
    const signer = await Signer.generate();
    const digest = computeNextDigest(signer.verfer.qb64);
    expect(digest).toHaveLength(44);
    expect(digest[0]).toBe('E');
  });

  it('is deterministic — same key produces same digest', async () => {
    const signer = await Signer.generate();
    const keyQb64 = signer.verfer.qb64;
    const d1 = computeNextDigest(keyQb64);
    const d2 = computeNextDigest(keyQb64);
    expect(d1).toBe(d2);
  });
});

describe('verifyPreRotation', () => {
  it('succeeds when keys match commitments', async () => {
    const signer = await Signer.generate();
    const keyQb64 = signer.verfer.qb64;
    const digest = computeNextDigest(keyQb64);

    const result = verifyPreRotation([keyQb64], [digest]);
    expect(result.bound).toBe(true);
    expect(result.mismatches).toHaveLength(0);
  });

  it('fails when key does not match commitment', async () => {
    const signer1 = await Signer.generate();
    const signer2 = await Signer.generate();
    const digest = computeNextDigest(signer1.verfer.qb64);

    const result = verifyPreRotation([signer2.verfer.qb64], [digest]);
    expect(result.bound).toBe(false);
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0].index).toBe(0);
    expect(result.mismatches[0].expected).toBe(digest);
  });

  it('with multiple keys — partial mismatch reports correct index', async () => {
    const signers = await Promise.all([
      Signer.generate(),
      Signer.generate(),
      Signer.generate(),
    ]);
    const keys = signers.map((s) => s.verfer.qb64);
    const digests = keys.map((k) => computeNextDigest(k));

    // Replace the middle key with a different one
    const rogue = await Signer.generate();
    const mixedKeys = [keys[0], rogue.verfer.qb64, keys[2]];

    const result = verifyPreRotation(mixedKeys, digests);
    expect(result.bound).toBe(false);
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0].index).toBe(1);
    expect(result.mismatches[0].expected).toBe(digests[1]);
  });
});

describe('isTransferable', () => {
  it('returns false for empty array', () => {
    expect(isTransferable([])).toBe(false);
  });

  it('returns true for non-empty array', () => {
    expect(isTransferable(['EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj'])).toBe(true);
  });
});

describe('isTransferableCode', () => {
  it('returns false for non-transferable codes', () => {
    expect(isTransferableCode('B')).toBe(false);    // Ed25519N
    expect(isTransferableCode('1AAA')).toBe(false);  // ECDSA_256k1N
    expect(isTransferableCode('1AAC')).toBe(false);  // Ed448N
    expect(isTransferableCode('1AAI')).toBe(false);  // ECDSA_256r1N
  });

  it('returns true for transferable codes', () => {
    expect(isTransferableCode('D')).toBe(true);     // Ed25519
    expect(isTransferableCode('1AAB')).toBe(true);  // ECDSA_256k1
    expect(isTransferableCode('1AAD')).toBe(true);  // Ed448
    expect(isTransferableCode('1AAJ')).toBe(true);  // ECDSA_256r1
  });
});
