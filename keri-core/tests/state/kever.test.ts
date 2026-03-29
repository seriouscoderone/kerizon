import { describe, it, expect } from 'vitest';
import { Signer, Diger } from '@kerizon/cesr';
import { incept } from '../../src/events/inception.js';
import { rotate } from '../../src/events/rotation.js';
import { interact } from '../../src/events/interaction.js';
import { Kever } from '../../src/state/kever.js';
import { TraitDex } from '../../src/state/traits.js';

async function makeKeypair() {
  const signer = await Signer.generate();
  const nextSigner = await Signer.generate();
  const nextDigest = Diger.digest(
    new TextEncoder().encode(nextSigner.verfer.qb64),
    'E',
  );
  return { signer, nextSigner, nextDigest };
}

describe('Kever', () => {
  it('initializes from inception with correct state', async () => {
    const { signer, nextDigest } = await makeKeypair();
    const serder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });
    const kever = Kever.fromInception(serder);

    expect(kever.prefix).toBe(serder.said);
    expect(kever.sn).toBe(0);
    expect(kever.transferable).toBe(true);
    expect(kever.currentKeys).toEqual([signer.verfer.qb64]);
    expect(kever.nextDigests).toEqual([nextDigest.qb64]);
    expect(kever.signingThreshold).toBe('1');
    expect(kever.nextThreshold).toBe('1');
    expect(kever.witnesses).toEqual([]);
    expect(kever.witnessThreshold).toBe(0);
    expect(kever.configTraits).toEqual([]);
    expect(kever.lastEstSn).toBe(0);
    expect(kever.lastEstSaid).toBe(serder.said);
  });

  it('applies rotation: sn increments, keys change, lastEstSn updates', async () => {
    const { signer, nextSigner, nextDigest } = await makeKeypair();
    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });
    const kever0 = Kever.fromInception(icpSerder);

    // Prepare next-next keys for rotation
    const nextNextSigner = await Signer.generate();
    const nextNextDigest = Diger.digest(
      new TextEncoder().encode(nextNextSigner.verfer.qb64),
      'E',
    );

    const rotSerder = rotate({
      prefix: kever0.prefix,
      priorDigest: icpSerder.said,
      sn: 1,
      keys: [nextSigner.verfer.qb64],
      nextDigests: [nextNextDigest.qb64],
    });
    const kever1 = kever0.applyEstablishment(rotSerder);

    expect(kever1.sn).toBe(1);
    expect(kever1.currentKeys).toEqual([nextSigner.verfer.qb64]);
    expect(kever1.nextDigests).toEqual([nextNextDigest.qb64]);
    expect(kever1.lastEstSn).toBe(1);
    expect(kever1.lastEstSaid).toBe(rotSerder.said);
    expect(kever1.prefix).toBe(kever0.prefix); // prefix never changes
  });

  it('applies interaction: sn increments, keys unchanged', async () => {
    const { signer, nextDigest } = await makeKeypair();
    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
    });
    const kever0 = Kever.fromInception(icpSerder);

    const ixnSerder = interact({
      prefix: kever0.prefix,
      priorDigest: icpSerder.said,
      sn: 1,
    });
    const kever1 = kever0.applyInteraction(ixnSerder);

    expect(kever1.sn).toBe(1);
    expect(kever1.currentKeys).toEqual(kever0.currentKeys);
    expect(kever1.nextDigests).toEqual(kever0.nextDigests);
    expect(kever1.lastEstSn).toBe(0); // unchanged from inception
    expect(kever1.lastEstSaid).toBe(icpSerder.said); // unchanged
  });

  it('EO trait rejects interaction', async () => {
    const { signer, nextDigest } = await makeKeypair();
    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [nextDigest.qb64],
      configTraits: [TraitDex.EstOnly],
    });
    const kever = Kever.fromInception(icpSerder);

    const ixnSerder = interact({
      prefix: kever.prefix,
      priorDigest: icpSerder.said,
      sn: 1,
    });

    expect(() => kever.applyInteraction(ixnSerder)).toThrow(
      'Establishment-only identifier: interaction events not allowed',
    );
  });

  it('non-transferable when nextDigests is empty', async () => {
    const { signer } = await makeKeypair();
    const icpSerder = incept({
      keys: [signer.verfer.qb64],
      nextDigests: [],
    });
    const kever = Kever.fromInception(icpSerder);

    expect(kever.transferable).toBe(false);
  });

  it('multiple rotations: sn increments correctly each time', async () => {
    const kp0 = await makeKeypair();
    const kp1 = await makeKeypair();
    const kp2 = await makeKeypair();
    const kp3 = await makeKeypair();

    const icpSerder = incept({
      keys: [kp0.signer.verfer.qb64],
      nextDigests: [kp0.nextDigest.qb64],
    });
    let kever = Kever.fromInception(icpSerder);
    expect(kever.sn).toBe(0);

    // First rotation
    const rot1 = rotate({
      prefix: kever.prefix,
      priorDigest: icpSerder.said,
      sn: 1,
      keys: [kp1.signer.verfer.qb64],
      nextDigests: [kp1.nextDigest.qb64],
    });
    kever = kever.applyEstablishment(rot1);
    expect(kever.sn).toBe(1);
    expect(kever.lastEstSn).toBe(1);

    // Second rotation
    const rot2 = rotate({
      prefix: kever.prefix,
      priorDigest: rot1.said,
      sn: 2,
      keys: [kp2.signer.verfer.qb64],
      nextDigests: [kp2.nextDigest.qb64],
    });
    kever = kever.applyEstablishment(rot2);
    expect(kever.sn).toBe(2);
    expect(kever.lastEstSn).toBe(2);

    // Third rotation
    const rot3 = rotate({
      prefix: kever.prefix,
      priorDigest: rot2.said,
      sn: 3,
      keys: [kp3.signer.verfer.qb64],
      nextDigests: [kp3.nextDigest.qb64],
    });
    kever = kever.applyEstablishment(rot3);
    expect(kever.sn).toBe(3);
    expect(kever.lastEstSn).toBe(3);
    expect(kever.currentKeys).toEqual([kp3.signer.verfer.qb64]);
  });

  it('interaction after rotation: sn correct, keys from last rotation', async () => {
    const kp0 = await makeKeypair();
    const kp1 = await makeKeypair();

    const icpSerder = incept({
      keys: [kp0.signer.verfer.qb64],
      nextDigests: [kp0.nextDigest.qb64],
    });
    let kever = Kever.fromInception(icpSerder);

    // Rotation
    const rotSerder = rotate({
      prefix: kever.prefix,
      priorDigest: icpSerder.said,
      sn: 1,
      keys: [kp1.signer.verfer.qb64],
      nextDigests: [kp1.nextDigest.qb64],
    });
    kever = kever.applyEstablishment(rotSerder);

    // Interaction after rotation
    const ixnSerder = interact({
      prefix: kever.prefix,
      priorDigest: rotSerder.said,
      sn: 2,
    });
    kever = kever.applyInteraction(ixnSerder);

    expect(kever.sn).toBe(2);
    expect(kever.currentKeys).toEqual([kp1.signer.verfer.qb64]); // keys from rotation
    expect(kever.lastEstSn).toBe(1); // still from rotation
    expect(kever.lastEstSaid).toBe(rotSerder.said);
  });

  it('witness changes in rotation: witnesses updated correctly', async () => {
    const kp0 = await makeKeypair();
    const kp1 = await makeKeypair();

    const wit1 = 'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha';
    const wit2 = 'BEOJlCDzz1bPMNQI6rE5Uh6RaGKxBPMbOlJMgnqwPHJx';
    const wit3 = 'BN8t3n1lxcV0SWGJIIF46fpSUqA7Mqre5KJNN3nbx3mr';

    const icpSerder = incept({
      keys: [kp0.signer.verfer.qb64],
      nextDigests: [kp0.nextDigest.qb64],
      witnesses: [wit1, wit2],
      witnessThreshold: 2,
    });
    let kever = Kever.fromInception(icpSerder);
    expect(kever.witnesses).toEqual([wit1, wit2]);
    expect(kever.witnessThreshold).toBe(2);

    // Rotate: remove wit1, add wit3
    const rotSerder = rotate({
      prefix: kever.prefix,
      priorDigest: icpSerder.said,
      sn: 1,
      keys: [kp1.signer.verfer.qb64],
      nextDigests: [kp1.nextDigest.qb64],
      witnessesToRemove: [wit1],
      witnessesToAdd: [wit3],
      witnessThreshold: 2,
    });
    kever = kever.applyEstablishment(rotSerder);

    expect(kever.witnesses).toEqual([wit2, wit3]); // wit1 removed, wit3 added
    expect(kever.witnessThreshold).toBe(2);
  });
});
