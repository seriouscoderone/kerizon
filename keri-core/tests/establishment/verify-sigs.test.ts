import { describe, it, expect } from 'vitest';
import { Signer, Siger, Diger } from '@kerizon/cesr';
import { verifySignatures } from '../../src/establishment/verify-sigs.js';
import { incept } from '../../src/events/inception.js';

async function makeKeypair() {
  const signer = await Signer.generate();
  const nextSigner = await Signer.generate();
  const nextDigest = Diger.digest(
    new TextEncoder().encode(nextSigner.verfer.qb64),
    'E',
  );
  return { signer, nextSigner, nextDigest };
}

describe('verifySignatures', () => {
  it('valid single signature -> verified true', async () => {
    const kp = await makeKeypair();
    const serder = incept({
      keys: [kp.signer.verfer.qb64],
      nextDigests: [kp.nextDigest.qb64],
    });

    const sigRaw = await kp.signer.sign(serder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });

    const result = await verifySignatures(
      serder.raw,
      [siger],
      [kp.signer.verfer.qb64],
      '1',
    );

    expect(result.verified).toBe(true);
    expect(result.verifiedIndices).toEqual([0]);
    expect(result.reason).toBeUndefined();
  });

  it('wrong signature -> verified false', async () => {
    const kp = await makeKeypair();
    const serder = incept({
      keys: [kp.signer.verfer.qb64],
      nextDigests: [kp.nextDigest.qb64],
    });

    // Sign with a different key (nextSigner, not the declared key)
    const wrongSigRaw = await kp.nextSigner.sign(serder.raw);
    const siger = Siger.create({ raw: wrongSigRaw, index: 0 });

    const result = await verifySignatures(
      serder.raw,
      [siger],
      [kp.signer.verfer.qb64],
      '1',
    );

    expect(result.verified).toBe(false);
    expect(result.verifiedIndices).toEqual([]);
    expect(result.reason).toContain('threshold not satisfied');
  });

  it('no signatures -> verified false with reason', async () => {
    const kp = await makeKeypair();

    const result = await verifySignatures(
      new Uint8Array([1, 2, 3]),
      [],
      [kp.signer.verfer.qb64],
      '1',
    );

    expect(result.verified).toBe(false);
    expect(result.verifiedIndices).toEqual([]);
    expect(result.reason).toBe('no signatures provided');
  });

  it('threshold not met (1 of 2 required) -> verified false', async () => {
    const kp0 = await makeKeypair();
    const kp1 = await makeKeypair();

    const serder = incept({
      keys: [kp0.signer.verfer.qb64, kp1.signer.verfer.qb64],
      nextDigests: [kp0.nextDigest.qb64, kp1.nextDigest.qb64],
      signingThreshold: '2',
    });

    // Only sign with key 0 — threshold requires 2
    const sigRaw = await kp0.signer.sign(serder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });

    const result = await verifySignatures(
      serder.raw,
      [siger],
      [kp0.signer.verfer.qb64, kp1.signer.verfer.qb64],
      '2',
    );

    expect(result.verified).toBe(false);
    expect(result.verifiedIndices).toEqual([0]);
    expect(result.reason).toContain('threshold not satisfied');
  });

  it('index out of range -> skipped, threshold check applies', async () => {
    const kp = await makeKeypair();
    const serder = incept({
      keys: [kp.signer.verfer.qb64],
      nextDigests: [kp.nextDigest.qb64],
    });

    const sigRaw = await kp.signer.sign(serder.raw);
    // Create siger with out-of-range index (5, but only 1 key)
    const siger = Siger.create({ raw: sigRaw, index: 5 });

    const result = await verifySignatures(
      serder.raw,
      [siger],
      [kp.signer.verfer.qb64],
      '1',
    );

    expect(result.verified).toBe(false);
    expect(result.verifiedIndices).toEqual([]);
    expect(result.reason).toContain('threshold not satisfied');
  });

  it('multiple valid signatures -> all indices returned', async () => {
    const kp0 = await makeKeypair();
    const kp1 = await makeKeypair();

    const serder = incept({
      keys: [kp0.signer.verfer.qb64, kp1.signer.verfer.qb64],
      nextDigests: [kp0.nextDigest.qb64, kp1.nextDigest.qb64],
      signingThreshold: '2',
    });

    const sigRaw0 = await kp0.signer.sign(serder.raw);
    const sigRaw1 = await kp1.signer.sign(serder.raw);
    const siger0 = Siger.create({ raw: sigRaw0, index: 0 });
    const siger1 = Siger.create({ raw: sigRaw1, index: 1 });

    const result = await verifySignatures(
      serder.raw,
      [siger0, siger1],
      [kp0.signer.verfer.qb64, kp1.signer.verfer.qb64],
      '2',
    );

    expect(result.verified).toBe(true);
    expect(result.verifiedIndices).toEqual([0, 1]);
  });
});
