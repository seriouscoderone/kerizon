import { describe, it, expect } from "vitest";
import { IdentifierState } from "../../../src/identifier-state.js";
import { InceptionBuilder } from "../../../src/builders/inception.js";
import { RotationBuilder } from "../../../src/builders/rotation.js";
import { InteractionBuilder } from "../../../src/builders/interaction.js";
import { DelegatedInceptionBuilder } from "../../../src/builders/delegated-inception.js";
import type { KeyStateSnapshot } from "../../../src/types.js";
import { generateKeyPair, testHashFn } from "../../helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeKeys(n: number): Promise<string[]> {
  const keys: string[] = [];
  for (let i = 0; i < n; i++) {
    const kp = await generateKeyPair();
    keys.push(kp.verferQb64);
  }
  return keys;
}

// ---------------------------------------------------------------------------
// SR01: snapshot after inception -> all fields correct
// ---------------------------------------------------------------------------

describe("IdentifierState snapshot/restore", () => {
  it("SR01: snapshot after inception -> all fields correct", async () => {
    const signingKeys = await makeKeys(2);
    const nextKeys = await makeKeys(2);
    const witnesses = await makeKeys(3);

    const icp = new InceptionBuilder(testHashFn)
      .signingKeys(signingKeys)
      .signingThreshold("2")
      .nextKeys(nextKeys)
      .nextKeyThreshold("1")
      .witnesses(witnesses)
      .witnessThreshold(2)
      .build();

    const state = IdentifierState.fromInception(icp.fields);
    const snap = state.snapshot();

    // Protocol version
    expect(snap.vn).toEqual([1, 0]);
    // Identifier
    expect(snap.i).toBe(icp.prefix);
    // Sequence number (hex)
    expect(snap.s).toBe("0");
    // Latest event SAID
    expect(snap.d).toBe(icp.said);
    // Prior event SAID (empty for inception)
    expect(snap.p).toBe("");
    // Event type
    expect(snap.et).toBe("icp");
    // Signing keys
    expect(snap.k).toEqual(signingKeys);
    // Signing threshold
    expect(snap.kt).toBe("2");
    // Next key digests
    expect(snap.n).toEqual(nextKeys);
    // Next threshold
    expect(snap.nt).toBe("1");
    // Witnesses
    expect(snap.b).toEqual(witnesses);
    // Witness threshold (hex)
    expect(snap.bt).toBe("2");
    // Config traits
    expect(snap.c).toEqual([]);
    // Delegator (empty for non-delegated)
    expect(snap.di).toBe("");
    // Establishment detail
    expect(snap.ee.s).toBe("0");
    expect(snap.ee.d).toBe(icp.said);
    expect(snap.ee.br).toEqual([]);
    expect(snap.ee.ba).toEqual([]);
  });

  // ---------------------------------------------------------------------------
  // SR02: snapshot after rotation -> updated keys/witnesses/thresholds
  // ---------------------------------------------------------------------------

  it("SR02: snapshot after rotation -> updated keys/witnesses/thresholds", async () => {
    const signingKeys1 = await makeKeys(1);
    const nextKeys1 = await makeKeys(1);
    const witnesses1 = await makeKeys(2);

    const icp = new InceptionBuilder(testHashFn)
      .signingKeys(signingKeys1)
      .nextKeys(nextKeys1)
      .witnesses(witnesses1)
      .witnessThreshold(1)
      .build();

    const state = IdentifierState.fromInception(icp.fields);

    // Build rotation with new keys and witness changes
    const newSigningKeys = await makeKeys(2);
    const newNextKeys = await makeKeys(2);
    const newWitness = (await makeKeys(1))[0];

    const rot = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys(newSigningKeys)
      .signingThreshold("2")
      .nextKeys(newNextKeys)
      .nextKeyThreshold("1")
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .currentWitnesses(witnesses1)
      .cutWitnesses([witnesses1[0]])
      .addWitnesses([newWitness])
      .witnessThreshold(1)
      .build();

    state.applyEvent(rot.fields);

    const snap = state.snapshot();

    // sn updated
    expect(snap.s).toBe("1");
    // Keys updated
    expect(snap.k).toEqual(newSigningKeys);
    expect(snap.kt).toBe("2");
    expect(snap.n).toEqual(newNextKeys);
    expect(snap.nt).toBe("1");
    // Witness list updated (removed witnesses1[0], added newWitness)
    expect(snap.b).toContain(witnesses1[1]);
    expect(snap.b).toContain(newWitness);
    expect(snap.b).not.toContain(witnesses1[0]);
    // bt hex 1
    expect(snap.bt).toBe("1");
    // Latest event SAID
    expect(snap.d).toBe(rot.said);
    // Event type
    expect(snap.et).toBe("rot");
    // Establishment detail tracks the rotation
    expect(snap.ee.s).toBe("1");
    expect(snap.ee.d).toBe(rot.said);
    expect(snap.ee.br).toEqual([witnesses1[0]]);
    expect(snap.ee.ba).toEqual([newWitness]);
  });

  // ---------------------------------------------------------------------------
  // SR03: snapshot after interaction -> sn updated, keys unchanged
  // ---------------------------------------------------------------------------

  it("SR03: snapshot after interaction -> sn updated, keys unchanged", async () => {
    const signingKeys = await makeKeys(1);
    const nextKeys = await makeKeys(1);

    const icp = new InceptionBuilder(testHashFn)
      .signingKeys(signingKeys)
      .nextKeys(nextKeys)
      .build();

    const state = IdentifierState.fromInception(icp.fields);
    const snapBefore = state.snapshot();

    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();

    state.applyEvent(ixn.fields);

    const snapAfter = state.snapshot();

    // sn incremented
    expect(snapAfter.s).toBe("1");
    // Keys unchanged
    expect(snapAfter.k).toEqual(snapBefore.k);
    expect(snapAfter.kt).toEqual(snapBefore.kt);
    expect(snapAfter.n).toEqual(snapBefore.n);
    expect(snapAfter.nt).toEqual(snapBefore.nt);
    // Witnesses unchanged
    expect(snapAfter.b).toEqual(snapBefore.b);
    expect(snapAfter.bt).toEqual(snapBefore.bt);
    // Event type is ixn
    expect(snapAfter.et).toBe("ixn");
    // Latest event SAID updated
    expect(snapAfter.d).toBe(ixn.said);
    // Establishment detail unchanged (ixn is not an establishment event)
    expect(snapAfter.ee.s).toBe(snapBefore.ee.s);
    expect(snapAfter.ee.d).toBe(snapBefore.ee.d);
  });

  // ---------------------------------------------------------------------------
  // SR04: fromSnapshot(snapshot) -> state matches original
  // ---------------------------------------------------------------------------

  it("SR04: fromSnapshot(snapshot) -> state matches original", async () => {
    const signingKeys = await makeKeys(2);
    const nextKeys = await makeKeys(2);
    const witnesses = await makeKeys(3);

    const icp = new InceptionBuilder(testHashFn)
      .signingKeys(signingKeys)
      .signingThreshold("2")
      .nextKeys(nextKeys)
      .nextKeyThreshold("1")
      .witnesses(witnesses)
      .witnessThreshold(2)
      .establishmentOnly()
      .doNotDelegate()
      .build();

    const state = IdentifierState.fromInception(icp.fields);
    const snap = state.snapshot();

    // Restore from snapshot
    const restored = IdentifierState.fromSnapshot(snap);

    expect(restored.prefix).toBe(state.prefix);
    expect(restored.sequenceNumber).toBe(state.sequenceNumber);
    expect(restored.latestEventSaid).toBe(state.latestEventSaid);
    expect(restored.eventIlk).toBe(state.eventIlk);
    expect(restored.signingKeys).toEqual(state.signingKeys);
    expect(restored.signingThreshold).toEqual(state.signingThreshold);
    expect(restored.nextKeyDigests).toEqual(state.nextKeyDigests);
    expect(restored.nextThreshold).toEqual(state.nextThreshold);
    expect(restored.witnesses).toEqual(state.witnesses);
    expect(restored.witnessThreshold).toBe(state.witnessThreshold);
    expect(restored.isDelegated).toBe(state.isDelegated);
    expect(restored.delegatorPrefix).toBe(state.delegatorPrefix);
    expect(restored.isEstablishmentOnly).toBe(state.isEstablishmentOnly);
    expect(restored.isDoNotDelegate).toBe(state.isDoNotDelegate);
    expect(restored.transferable).toBe(state.transferable);
    expect(restored.lastEstablishment).toEqual(state.lastEstablishment);

    // Snapshot roundtrip
    const restoredSnap = restored.snapshot();
    expect(restoredSnap).toEqual(snap);
  });

  // ---------------------------------------------------------------------------
  // SR05: Restore from snapshot -> apply next event -> consistent state
  // ---------------------------------------------------------------------------

  it("SR05: restore from snapshot -> apply next event -> consistent", async () => {
    const signingKeys = await makeKeys(1);
    const nextKeys = await makeKeys(1);

    const icp = new InceptionBuilder(testHashFn)
      .signingKeys(signingKeys)
      .nextKeys(nextKeys)
      .build();

    const state = IdentifierState.fromInception(icp.fields);
    const snap = state.snapshot();

    // Restore and apply an interaction
    const restored = IdentifierState.fromSnapshot(snap);

    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();

    restored.applyEvent(ixn.fields);

    expect(restored.sequenceNumber).toBe(1);
    expect(restored.latestEventSaid).toBe(ixn.said);
    expect(restored.eventIlk).toBe("ixn");
    // Keys unchanged
    expect(restored.signingKeys).toEqual(signingKeys);
    expect(restored.nextKeyDigests).toEqual(nextKeys);
  });

  // ---------------------------------------------------------------------------
  // SR06: Delegated identifier snapshot includes delegator prefix
  // ---------------------------------------------------------------------------

  it("SR06: delegated identifier snapshot includes delegator prefix", async () => {
    const signingKeys = await makeKeys(1);
    const delegatorPrefix = "EDelegator0000000000000000000000000000000000";

    const dip = new DelegatedInceptionBuilder(testHashFn)
      .delegator(delegatorPrefix)
      .signingKeys(signingKeys)
      .build();

    const state = IdentifierState.fromInception(dip.fields);
    const snap = state.snapshot();

    expect(snap.di).toBe(delegatorPrefix);
    expect(state.isDelegated).toBe(true);
    expect(state.delegatorPrefix).toBe(delegatorPrefix);

    // Restore and check
    const restored = IdentifierState.fromSnapshot(snap);
    expect(restored.isDelegated).toBe(true);
    expect(restored.delegatorPrefix).toBe(delegatorPrefix);
  });

  // ---------------------------------------------------------------------------
  // SR07: EstablishmentDetail (ee field) correctly tracks last est event
  // ---------------------------------------------------------------------------

  it("SR07: EstablishmentDetail tracks last establishment event", async () => {
    const signingKeys1 = await makeKeys(1);
    const nextKeys1 = await makeKeys(1);

    const icp = new InceptionBuilder(testHashFn)
      .signingKeys(signingKeys1)
      .nextKeys(nextKeys1)
      .build();

    const state = IdentifierState.fromInception(icp.fields);

    // After inception: ee points to inception
    let snap = state.snapshot();
    expect(snap.ee.s).toBe("0");
    expect(snap.ee.d).toBe(icp.said);

    // Apply an interaction
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();
    state.applyEvent(ixn.fields);

    // After interaction: ee still points to inception (ixn is not establishment)
    snap = state.snapshot();
    expect(snap.ee.s).toBe("0");
    expect(snap.ee.d).toBe(icp.said);
    expect(snap.s).toBe("1"); // sn advanced

    // Apply a rotation
    const newSigningKeys = await makeKeys(1);
    const newNextKeys = await makeKeys(1);

    const rot = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys(newSigningKeys)
      .nextKeys(newNextKeys)
      .previousEvent(ixn.said)
      .sequenceNumber(2)
      .build();
    state.applyEvent(rot.fields);

    // After rotation: ee points to the rotation event
    snap = state.snapshot();
    expect(snap.ee.s).toBe("2");
    expect(snap.ee.d).toBe(rot.said);
    expect(snap.s).toBe("2"); // sn advanced
    expect(snap.et).toBe("rot");
  });
});
