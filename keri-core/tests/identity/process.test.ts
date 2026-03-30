import { describe, it, expect } from 'vitest';
import { Signer, Siger, Diger } from '@kerizon/cesr';
import { incept } from '../../src/events/inception.js';
import { rotate } from '../../src/events/rotation.js';
import { interact } from '../../src/events/interaction.js';
import { Kever } from '../../src/state/kever.js';
import { TraitDex } from '../../src/state/traits.js';
import { processEvent } from '../../src/identity/process.js';

async function makeKeypair() {
  const signer = await Signer.generate();
  const nextSigner = await Signer.generate();
  const nextDigest = Diger.digest(
    new TextEncoder().encode(nextSigner.verfer.qb64),
    'E',
  );
  return { signer, nextSigner, nextDigest };
}

class SimpleKeverStore {
  private kevers = new Map<string, Kever>();
  get(p: string) { return this.kevers.get(p); }
  set(p: string, k: Kever) { this.kevers.set(p, k); }
  getLastSaid(p: string) { return this.kevers.get(p)?.lastEstSaid; }
  getExpectedSn(p: string) { return (this.kevers.get(p)?.sn ?? -1) + 1; }
}

describe('processEvent', () => {
  it('inception: unknown prefix + icp -> accepted, sn=0', async () => {
    const store = new SimpleKeverStore();
    const { signer, nextDigest } = await makeKeypair();
    const serder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });

    const result = await processEvent(serder, store);
    expect(result).toEqual({
      status: 'accepted',
      aid: serder.pre,
      sn: 0,
      said: serder.said,
    });
    expect(store.get(serder.pre)).toBeDefined();
  });

  it('unknown prefix + rot -> escrowed OOE', async () => {
    const store = new SimpleKeverStore();
    const { signer, nextSigner, nextDigest } = await makeKeypair();

    // Create a rotation event for a prefix that doesn't exist in the store
    const rotSerder = rotate({
      prefix: 'ENonexistent00000000000000000000000000000000',
      priorDigest: 'EFakeDigest0000000000000000000000000000000000',
      sn: 1,
      keys: [nextSigner.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });

    const result = await processEvent(rotSerder, store);
    expect(result.status).toBe('escrowed');
    if (result.status === 'escrowed') {
      expect(result.escrowType).toBe('OOE');
      expect(result.reason).toContain('unknown prefix');
    }
  });

  it('rotation at expected sn -> accepted', async () => {
    const store = new SimpleKeverStore();
    const kp0 = await makeKeypair();
    const kp1 = await makeKeypair();

    // Inception
    const icpSerder = incept({
      keys: [kp0.signer.verfer.qb64],
      nextDigests: [kp0.nextDigest.qb64],
    });
    await processEvent(icpSerder, store);

    // Rotation at sn=1
    const rotSerder = rotate({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 1,
      keys: [kp1.signer.verfer.qb64],
      nextDigests: [kp1.nextDigest.qb64],
    });
    const result = await processEvent(rotSerder, store);

    expect(result).toEqual({
      status: 'accepted',
      aid: icpSerder.pre,
      sn: 1,
      said: rotSerder.said,
    });
  });

  it('interaction at expected sn -> accepted', async () => {
    const store = new SimpleKeverStore();
    const { signer, nextDigest } = await makeKeypair();

    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });
    await processEvent(icpSerder, store);

    const ixnSerder = interact({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 1,
    });
    const result = await processEvent(ixnSerder, store);

    expect(result).toEqual({
      status: 'accepted',
      aid: icpSerder.pre,
      sn: 1,
      said: ixnSerder.said,
    });
  });

  it('out of order (sn > expected) -> escrowed OOE', async () => {
    const store = new SimpleKeverStore();
    const { signer, nextSigner, nextDigest } = await makeKeypair();
    const kp1 = await makeKeypair();

    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });
    await processEvent(icpSerder, store);

    // Jump to sn=5 when expected is 1
    const rotSerder = rotate({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 5,
      keys: [kp1.signer.verfer.qb64],
      nextDigests: [kp1.nextDigest.qb64],
    });
    const result = await processEvent(rotSerder, store);

    expect(result.status).toBe('escrowed');
    if (result.status === 'escrowed') {
      expect(result.escrowType).toBe('OOE');
      expect(result.reason).toContain('expected sn=1');
      expect(result.reason).toContain('got sn=5');
    }
  });

  it('duplicate (sn < expected) -> duplicate', async () => {
    const store = new SimpleKeverStore();
    const kp0 = await makeKeypair();
    const kp1 = await makeKeypair();

    const icpSerder = incept({
      keys: [kp0.signer.verfer.qb64],
      nextDigests: [kp0.nextDigest.qb64],
    });
    await processEvent(icpSerder, store);

    // Rotation at sn=1
    const rotSerder = rotate({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 1,
      keys: [kp1.signer.verfer.qb64],
      nextDigests: [kp1.nextDigest.qb64],
    });
    await processEvent(rotSerder, store);

    // Re-send icp (sn=0) — now sn < expectedSn (2)
    const result = await processEvent(icpSerder, store);
    expect(result).toEqual({
      status: 'duplicate',
      aid: icpSerder.pre,
      sn: 0,
    });
  });

  it('EO identifier rejects ixn -> rejected', async () => {
    const store = new SimpleKeverStore();
    const { signer, nextDigest } = await makeKeypair();

    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
      configTraits: [TraitDex.EstOnly],
    });
    await processEvent(icpSerder, store);

    const ixnSerder = interact({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 1,
    });
    const result = await processEvent(ixnSerder, store);

    expect(result.status).toBe('rejected');
    if (result.status === 'rejected') {
      expect(result.reason).toContain('Establishment-only');
    }
  });

  it('sequential: icp -> rot -> ixn -> all accepted with correct sn', async () => {
    const store = new SimpleKeverStore();
    const kp0 = await makeKeypair();
    const kp1 = await makeKeypair();

    // icp at sn=0
    const icpSerder = incept({
      keys: [kp0.signer.verfer.qb64],
      nextDigests: [kp0.nextDigest.qb64],
    });
    const r1 = await processEvent(icpSerder, store);
    expect(r1).toEqual({ status: 'accepted', aid: icpSerder.pre, sn: 0, said: icpSerder.said });

    // rot at sn=1
    const rotSerder = rotate({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 1,
      keys: [kp1.signer.verfer.qb64],
      nextDigests: [kp1.nextDigest.qb64],
    });
    const r2 = await processEvent(rotSerder, store);
    expect(r2).toEqual({ status: 'accepted', aid: icpSerder.pre, sn: 1, said: rotSerder.said });

    // ixn at sn=2
    const ixnSerder = interact({
      prefix: icpSerder.pre,
      priorDigest: rotSerder.said,
      sn: 2,
    });
    const r3 = await processEvent(ixnSerder, store);
    expect(r3).toEqual({ status: 'accepted', aid: icpSerder.pre, sn: 2, said: ixnSerder.said });
  });

  it('non-transferable rejects rotation -> rejected', async () => {
    const store = new SimpleKeverStore();
    const { signer } = await makeKeypair();
    const kp1 = await makeKeypair();

    // Non-transferable: empty nextDigests
    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [],
    });
    await processEvent(icpSerder, store);

    const rotSerder = rotate({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 1,
      keys: [kp1.signer.verfer.qb64],
      nextDigests: [kp1.nextDigest.qb64],
    });
    const result = await processEvent(rotSerder, store);

    expect(result.status).toBe('rejected');
    if (result.status === 'rejected') {
      expect(result.reason).toContain('non-transferable');
    }
  });

  it('inception with valid sigers -> accepted', async () => {
    const store = new SimpleKeverStore();
    const { signer, nextDigest } = await makeKeypair();
    const serder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });

    const sigRaw = await signer.sign(serder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });

    const result = await processEvent(serder, store, [siger]);
    expect(result).toEqual({
      status: 'accepted',
      aid: serder.pre,
      sn: 0,
      said: serder.said,
    });
  });

  it('inception with bad sigers -> rejected', async () => {
    const store = new SimpleKeverStore();
    const kp = await makeKeypair();
    const serder = incept({
      keys: [kp.signer.verfer.qb64],
      nextDigests: [kp.nextDigest.qb64],
    });

    // Sign with nextSigner (wrong key)
    const wrongSigRaw = await kp.nextSigner.sign(serder.raw);
    const badSiger = Siger.create({ raw: wrongSigRaw, index: 0 });

    const result = await processEvent(serder, store, [badSiger]);
    expect(result.status).toBe('rejected');
    if (result.status === 'rejected') {
      expect(result.reason).toContain('threshold not satisfied');
    }
    // Kever should NOT have been created
    expect(store.get(serder.pre)).toBeUndefined();
  });

  it('interaction with valid sigers -> accepted', async () => {
    const store = new SimpleKeverStore();
    const { signer, nextDigest } = await makeKeypair();

    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });
    await processEvent(icpSerder, store);

    const ixnSerder = interact({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 1,
    });

    const sigRaw = await signer.sign(ixnSerder.raw);
    const siger = Siger.create({ raw: sigRaw, index: 0 });

    const result = await processEvent(ixnSerder, store, [siger]);
    expect(result).toEqual({
      status: 'accepted',
      aid: icpSerder.pre,
      sn: 1,
      said: ixnSerder.said,
    });
  });

  it('interaction with bad sigers -> rejected', async () => {
    const store = new SimpleKeverStore();
    const kp = await makeKeypair();

    const icpSerder = incept({
      keys: [kp.signer.verfer.qb64],
      nextDigests: [kp.nextDigest.qb64],
    });
    await processEvent(icpSerder, store);

    const ixnSerder = interact({
      prefix: icpSerder.pre,
      priorDigest: icpSerder.said,
      sn: 1,
    });

    // Sign with the wrong key
    const wrongSigRaw = await kp.nextSigner.sign(ixnSerder.raw);
    const badSiger = Siger.create({ raw: wrongSigRaw, index: 0 });

    const result = await processEvent(ixnSerder, store, [badSiger]);
    expect(result.status).toBe('rejected');
    if (result.status === 'rejected') {
      expect(result.reason).toContain('threshold not satisfied');
    }
  });

  it('existing tests without sigers still work (backward compat)', async () => {
    const store = new SimpleKeverStore();
    const { signer, nextDigest } = await makeKeypair();
    const serder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });

    // No sigers argument -- should still accept
    const result = await processEvent(serder, store);
    expect(result.status).toBe('accepted');
  });
});
