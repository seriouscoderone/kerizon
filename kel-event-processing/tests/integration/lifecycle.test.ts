import { describe, it, expect } from "vitest";
import { EventProcessor } from "../../src/event-processor.js";
import { DomainEventBus } from "../../src/domain-events.js";
import { InMemoryEventRepository, DefaultCryptoProvider } from "../../src/repository/memory.js";
import { InceptionBuilder } from "../../src/builders/inception.js";
import { RotationBuilder } from "../../src/builders/rotation.js";
import { InteractionBuilder } from "../../src/builders/interaction.js";
import { DelegatedInceptionBuilder } from "../../src/builders/delegated-inception.js";
import { IdentifierState } from "../../src/identifier-state.js";
import { EscrowType } from "../../src/repository/interface.js";
import { generateKeyPair, signMessage, testHashFn } from "../helpers.js";
import { encodeEd25519IndexedSig } from "../helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeProcessor(config?: Record<string, unknown>) {
  const repo = new InMemoryEventRepository();
  const bus = new DomainEventBus();
  const crypto = new DefaultCryptoProvider();
  const processor = new EventProcessor(repo, bus, crypto, config as any);
  return { repo, bus, crypto, processor };
}

type KP = Awaited<ReturnType<typeof generateKeyPair>>;

async function makeSignedSiger(kp: KP, raw: Uint8Array, index: number) {
  const sigBytes = await signMessage(kp.privateKey, raw);
  const qb64 = encodeEd25519IndexedSig(sigBytes, index);
  return { index, raw: sigBytes, qb64 };
}

// ---------------------------------------------------------------------------
// L01: inception -> rotation -> interaction
// ---------------------------------------------------------------------------

describe("Lifecycle tests", () => {
  it("L01: inception -> rotation -> interaction", async () => {
    const { processor, bus, repo } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();

    // -- Inception --
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);

    let state = processor.identifiers.get(icp.prefix)!;
    expect(state).toBeDefined();
    expect(state.sequenceNumber).toBe(0);
    expect(state.signingKeys).toEqual([kp1.verferQb64]);
    expect(state.latestEventSaid).toBe(icp.said);

    // -- Rotation --
    const rot = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();

    const rotSiger = await makeSignedSiger(kp2, rot.raw, 0);
    await processor.ingestEvent({ raw: rot.raw, fields: rot.fields }, [rotSiger]);

    state = processor.identifiers.get(icp.prefix)!;
    expect(state.sequenceNumber).toBe(1);
    expect(state.signingKeys).toEqual([kp2.verferQb64]);
    expect(state.nextKeyDigests).toEqual([kp3.verferQb64]);
    expect(state.latestEventSaid).toBe(rot.said);

    // -- Interaction --
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(rot.said)
      .sequenceNumber(2)
      .build();

    const ixnSiger = await makeSignedSiger(kp2, ixn.raw, 0);
    await processor.ingestEvent({ raw: ixn.raw, fields: ixn.fields }, [ixnSiger]);

    state = processor.identifiers.get(icp.prefix)!;
    expect(state.sequenceNumber).toBe(2);
    expect(state.signingKeys).toEqual([kp2.verferQb64]); // unchanged
    expect(state.latestEventSaid).toBe(ixn.said);

    // All three should have produced EventAccepted
    const events = bus.drain();
    const accepted = events.filter((e) => e.type === "EventAccepted");
    expect(accepted).toHaveLength(3);
  });

  // ---------------------------------------------------------------------------
  // L02: inception -> rot1 -> rot2 -> rot3 (key state evolves)
  // ---------------------------------------------------------------------------

  it("L02: inception -> rot1 -> rot2 -> rot3", async () => {
    const { processor } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();
    const kp4 = await generateKeyPair();
    const kp5 = await generateKeyPair(); // extra next key for final rotation

    // Inception
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);

    let prevSaid = icp.said;

    // Rotation 1: kp1 -> kp2, next=kp3
    const rot1 = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .previousEvent(prevSaid)
      .sequenceNumber(1)
      .build();
    const rot1Siger = await makeSignedSiger(kp2, rot1.raw, 0);
    await processor.ingestEvent({ raw: rot1.raw, fields: rot1.fields }, [rot1Siger]);
    prevSaid = rot1.said;

    // Rotation 2: kp2 -> kp3, next=kp4
    const rot2 = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp3.verferQb64])
      .nextKeys([kp4.verferQb64])
      .previousEvent(prevSaid)
      .sequenceNumber(2)
      .build();
    const rot2Siger = await makeSignedSiger(kp3, rot2.raw, 0);
    await processor.ingestEvent({ raw: rot2.raw, fields: rot2.fields }, [rot2Siger]);
    prevSaid = rot2.said;

    // Rotation 3: kp3 -> kp4, next=kp5
    const rot3 = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp4.verferQb64])
      .nextKeys([kp5.verferQb64])
      .previousEvent(prevSaid)
      .sequenceNumber(3)
      .build();
    const rot3Siger = await makeSignedSiger(kp4, rot3.raw, 0);
    await processor.ingestEvent({ raw: rot3.raw, fields: rot3.fields }, [rot3Siger]);

    const state = processor.identifiers.get(icp.prefix)!;
    expect(state.sequenceNumber).toBe(3);
    expect(state.signingKeys).toEqual([kp4.verferQb64]);
    expect(state.nextKeyDigests).toEqual([kp5.verferQb64]);
    expect(state.lastEstablishment.sn).toBe(3);
  });

  // ---------------------------------------------------------------------------
  // L03: icp -> ixn -> rot -> ixn -> rot (interleaving)
  // ---------------------------------------------------------------------------

  it("L03: icp -> ixn -> rot -> ixn -> rot interleaving", async () => {
    const { processor } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();

    // Inception
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();
    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);
    let prevSaid = icp.said;

    // ixn at sn=1
    const ixn1 = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(prevSaid)
      .sequenceNumber(1)
      .build();
    const ixn1Siger = await makeSignedSiger(kp1, ixn1.raw, 0);
    await processor.ingestEvent({ raw: ixn1.raw, fields: ixn1.fields }, [ixn1Siger]);
    prevSaid = ixn1.said;

    // rot at sn=2
    const rot1 = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .previousEvent(prevSaid)
      .sequenceNumber(2)
      .build();
    const rot1Siger = await makeSignedSiger(kp2, rot1.raw, 0);
    await processor.ingestEvent({ raw: rot1.raw, fields: rot1.fields }, [rot1Siger]);
    prevSaid = rot1.said;

    let state = processor.identifiers.get(icp.prefix)!;
    expect(state.sequenceNumber).toBe(2);
    expect(state.signingKeys).toEqual([kp2.verferQb64]);

    // ixn at sn=3
    const ixn2 = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(prevSaid)
      .sequenceNumber(3)
      .build();
    const ixn2Siger = await makeSignedSiger(kp2, ixn2.raw, 0);
    await processor.ingestEvent({ raw: ixn2.raw, fields: ixn2.fields }, [ixn2Siger]);
    prevSaid = ixn2.said;

    // rot at sn=4
    const kp4 = await generateKeyPair();
    const rot2 = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp3.verferQb64])
      .nextKeys([kp4.verferQb64])
      .previousEvent(prevSaid)
      .sequenceNumber(4)
      .build();
    const rot2Siger = await makeSignedSiger(kp3, rot2.raw, 0);
    await processor.ingestEvent({ raw: rot2.raw, fields: rot2.fields }, [rot2Siger]);

    state = processor.identifiers.get(icp.prefix)!;
    expect(state.sequenceNumber).toBe(4);
    expect(state.signingKeys).toEqual([kp3.verferQb64]);
    expect(state.lastEstablishment.sn).toBe(4);
  });

  // ---------------------------------------------------------------------------
  // L04: Delegated lifecycle (simplified)
  // ---------------------------------------------------------------------------

  it("L04: delegated inception lifecycle", async () => {
    const { processor, bus } = makeProcessor({ directMode: true });

    // Delegator inception
    const dkp1 = await generateKeyPair();
    const dkp2 = await generateKeyPair();

    const delegatorIcp = new InceptionBuilder(testHashFn)
      .signingKeys([dkp1.verferQb64])
      .nextKeys([dkp2.verferQb64])
      .build();

    const delegatorSiger = await makeSignedSiger(dkp1, delegatorIcp.raw, 0);
    await processor.ingestEvent(
      { raw: delegatorIcp.raw, fields: delegatorIcp.fields },
      [delegatorSiger],
    );

    // Delegate inception (dip)
    const skp1 = await generateKeyPair();
    const skp2 = await generateKeyPair();

    const dip = new DelegatedInceptionBuilder(testHashFn)
      .delegator(delegatorIcp.prefix)
      .signingKeys([skp1.verferQb64])
      .nextKeys([skp2.verferQb64])
      .build();

    const dipSiger = await makeSignedSiger(skp1, dip.raw, 0);
    await processor.ingestEvent(
      { raw: dip.raw, fields: dip.fields },
      [dipSiger],
    );

    const delegateState = processor.identifiers.get(dip.prefix)!;
    expect(delegateState).toBeDefined();
    expect(delegateState.isDelegated).toBe(true);
    expect(delegateState.delegatorPrefix).toBe(delegatorIcp.prefix);
    expect(delegateState.sequenceNumber).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // L05: Non-transferable: inception -> interaction only
  // ---------------------------------------------------------------------------

  it("L05: non-transferable identifier cannot rotate", async () => {
    const { processor } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();

    // Non-transferable inception (no next keys)
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      // No .nextKeys() -> non-transferable
      .build();

    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);

    const state = processor.identifiers.get(icp.prefix)!;
    expect(state.transferable).toBe(false);
    expect(state.nextKeyDigests).toEqual([]);

    // Rotation should fail via IdentifierState validation
    const kp2 = await generateKeyPair();
    const rot = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp2.verferQb64])
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();

    const rotSiger = await makeSignedSiger(kp2, rot.raw, 0);

    // Should not throw (routes to escrow or fails gracefully)
    // The applyEvent in IdentifierState will throw ValidationError
    // which is not an escrow-routable error, so it should be re-thrown
    await expect(
      processor.ingestEvent({ raw: rot.raw, fields: rot.fields }, [rotSiger]),
    ).rejects.toThrow(/non-transferable/i);
  });

  // ---------------------------------------------------------------------------
  // L06: Witnessed identifier with TOAD
  // ---------------------------------------------------------------------------

  it("L06: witnessed identifier with TOAD", async () => {
    const { processor } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    const wit1 = await generateKeyPair();
    const wit2 = await generateKeyPair();
    const wit3 = await generateKeyPair();

    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .witnesses([wit1.verferQb64, wit2.verferQb64, wit3.verferQb64])
      .witnessThreshold(2)
      .build();

    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);

    const state = processor.identifiers.get(icp.prefix)!;
    expect(state.witnesses).toHaveLength(3);
    expect(state.witnessThreshold).toBe(2);
    expect(state.witnesses).toEqual([
      wit1.verferQb64,
      wit2.verferQb64,
      wit3.verferQb64,
    ]);
  });

  // ---------------------------------------------------------------------------
  // L07: Multiple AIDs through same processor
  // ---------------------------------------------------------------------------

  it("L07: multiple AIDs through same processor", async () => {
    const { processor, bus } = makeProcessor({ directMode: true });

    // AID 1
    const kp1a = await generateKeyPair();
    const kp1b = await generateKeyPair();
    const icp1 = new InceptionBuilder(testHashFn)
      .signingKeys([kp1a.verferQb64])
      .nextKeys([kp1b.verferQb64])
      .build();
    const siger1 = await makeSignedSiger(kp1a, icp1.raw, 0);
    await processor.ingestEvent({ raw: icp1.raw, fields: icp1.fields }, [siger1]);

    // AID 2
    const kp2a = await generateKeyPair();
    const kp2b = await generateKeyPair();
    const icp2 = new InceptionBuilder(testHashFn)
      .signingKeys([kp2a.verferQb64])
      .nextKeys([kp2b.verferQb64])
      .build();
    const siger2 = await makeSignedSiger(kp2a, icp2.raw, 0);
    await processor.ingestEvent({ raw: icp2.raw, fields: icp2.fields }, [siger2]);

    // AID 3
    const kp3a = await generateKeyPair();
    const kp3b = await generateKeyPair();
    const icp3 = new InceptionBuilder(testHashFn)
      .signingKeys([kp3a.verferQb64])
      .nextKeys([kp3b.verferQb64])
      .build();
    const siger3 = await makeSignedSiger(kp3a, icp3.raw, 0);
    await processor.ingestEvent({ raw: icp3.raw, fields: icp3.fields }, [siger3]);

    expect(processor.identifiers.size).toBe(3);
    expect(processor.identifiers.has(icp1.prefix)).toBe(true);
    expect(processor.identifiers.has(icp2.prefix)).toBe(true);
    expect(processor.identifiers.has(icp3.prefix)).toBe(true);

    // Each AID has independent state
    const state1 = processor.identifiers.get(icp1.prefix)!;
    const state2 = processor.identifiers.get(icp2.prefix)!;
    expect(state1.signingKeys).toEqual([kp1a.verferQb64]);
    expect(state2.signingKeys).toEqual([kp2a.verferQb64]);

    const events = bus.drain();
    expect(events.filter((e) => e.type === "EventAccepted")).toHaveLength(3);
  });

  // ---------------------------------------------------------------------------
  // L08: Receipt flow
  // ---------------------------------------------------------------------------

  it("L08: receipt storage via ingestReceipt", async () => {
    const { processor, repo } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    // Ingest inception
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();
    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);

    // Build receipt fields
    const receiptFields = {
      v: "KERI10JSON000000_",
      t: "rct",
      d: icp.said,
      i: icp.prefix,
      s: "0",
    };
    const receiptRaw = new TextEncoder().encode(JSON.stringify(receiptFields));

    // Ingest receipt with non-transferable signature
    const witnessKp = await generateKeyPair();
    const cigarSigBytes = await signMessage(witnessKp.privateKey, icp.raw);

    await processor.ingestReceipt(
      { raw: receiptRaw, fields: receiptFields },
      {
        nonTransferableSignatures: [
          {
            verferQb64: witnessKp.verferQb64,
            sigRaw: cigarSigBytes,
          },
        ],
      },
    );

    // Verify receipt was stored
    const receipts = await repo.retrieveNonTransferableReceipts(icp.prefix, icp.said);
    expect(receipts).toHaveLength(1);
    expect(receipts[0].receiptorPrefix).toBe(witnessKp.verferQb64);
  });

  // ---------------------------------------------------------------------------
  // L09: Out-of-order resolution
  // ---------------------------------------------------------------------------

  it("L09: out-of-order event gets escrowed", async () => {
    const { processor, repo, bus } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();

    // Ingest inception
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();
    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);

    // Skip sn=1, submit sn=2 directly (out of order)
    // First build the rotation at sn=1 we'll insert later
    const rot1 = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();

    // Build interaction at sn=2 (referencing rot1 as prior)
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(rot1.said)
      .sequenceNumber(2)
      .build();

    const ixnSiger = await makeSignedSiger(kp2, ixn.raw, 0);

    // This should get escrowed (OOE) because sn=2 but expected sn=1
    await processor.ingestEvent({ raw: ixn.raw, fields: ixn.fields }, [ixnSiger]);

    // Verify it went to OOE escrow
    const ooeEntries: Array<{ prefix: string; sn: number; digest: string }> = [];
    for await (const entry of repo.iterateEscrow(EscrowType.OOE)) {
      ooeEntries.push(entry);
    }
    expect(ooeEntries.length).toBeGreaterThanOrEqual(1);
    const escrowedIxn = ooeEntries.find((e) => e.digest === ixn.said);
    expect(escrowedIxn).toBeDefined();
    expect(escrowedIxn!.sn).toBe(2);
  });

  // ---------------------------------------------------------------------------
  // L10: Recovery rotation
  // ---------------------------------------------------------------------------

  it("L10: recovery rotation supersedes interaction", async () => {
    const { processor } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();

    // Inception
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();
    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);

    // Interaction at sn=1
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();
    const ixnSiger = await makeSignedSiger(kp1, ixn.raw, 0);
    await processor.ingestEvent({ raw: ixn.raw, fields: ixn.fields }, [ixnSiger]);

    let state = processor.identifiers.get(icp.prefix)!;
    expect(state.sequenceNumber).toBe(1);
    expect(state.lastEstablishment.sn).toBe(0); // last est is still icp

    // Recovery rotation at sn=1 (superseding the interaction)
    // For recovery: lastEstSn (0) < sn (1) <= keverSn (1) — valid recovery
    const recoveryRot = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .previousEvent(icp.said) // points back to icp, not ixn
      .sequenceNumber(1)
      .build();
    const recoveryRotSiger = await makeSignedSiger(kp2, recoveryRot.raw, 0);
    await processor.ingestEvent(
      { raw: recoveryRot.raw, fields: recoveryRot.fields },
      [recoveryRotSiger],
    );

    state = processor.identifiers.get(icp.prefix)!;
    // Recovery rotation accepted: keys rotated
    expect(state.sequenceNumber).toBe(1);
    expect(state.signingKeys).toEqual([kp2.verferQb64]);
    expect(state.lastEstablishment.sn).toBe(1);
  });

  // ---------------------------------------------------------------------------
  // L11: Full escrow cascade (simplified)
  // ---------------------------------------------------------------------------

  it("L11: escrow cascade - OOE escrow populated and timeout triggers EventQueryNeeded", async () => {
    const { processor, repo, bus } = makeProcessor({
      directMode: true,
    });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    // Inception
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();
    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);
    bus.drain(); // clear inception event

    // Send out-of-order event at sn=5 (way ahead)
    const futureIxn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent("EFAKE000000000000000000000000000000000000000")
      .sequenceNumber(5)
      .build();
    const futureSiger = await makeSignedSiger(kp1, futureIxn.raw, 0);
    await processor.ingestEvent(
      { raw: futureIxn.raw, fields: futureIxn.fields },
      [futureSiger],
    );

    // Verify it's in OOE escrow
    const ooeEntries: Array<{ prefix: string; sn: number; digest: string }> = [];
    for await (const entry of repo.iterateEscrow(EscrowType.OOE)) {
      ooeEntries.push(entry);
    }
    expect(ooeEntries.length).toBeGreaterThanOrEqual(1);

    // Manually set the datetime to be expired (force timeout)
    // The datetime was already stored by routeToEscrow. We need to overwrite it.
    // Since storeDatetime is write-once, we need to directly manipulate the repo internals.
    // Instead, we create a new processor with very short timeout.
    const repo2 = new InMemoryEventRepository();
    const bus2 = new DomainEventBus();
    const crypto2 = new DefaultCryptoProvider();
    const processor2 = new EventProcessor(repo2, bus2, crypto2, { directMode: true }, {
      outOfOrder: 0, // 0 seconds timeout -> immediately expired
      partialSignatures: 3600,
      partialWitnesses: 3600,
      partialDelegation: 3600,
      delegable: 3600,
      misfitSource: 3600,
      unverifiedWitnessReceipt: 3600,
      unverifiedReceipt: 3600,
      unverifiedTransferableReceipt: 3600,
      likelyDuplicitous: 3600,
    });

    // Set up escrow entry in repo2
    const prefix = icp.prefix;
    const digest = futureIxn.said;
    await repo2.addToEscrow(EscrowType.OOE, prefix, 5, digest);
    await repo2.storeDatetime(prefix, digest, new Date(Date.now() - 1000).toISOString());

    // Run escrow resolution
    await processor2.resolveEscrows();

    const queryEvents = bus2.drain().filter((e) => e.type === "EventQueryNeeded");
    expect(queryEvents.length).toBeGreaterThanOrEqual(1);
    expect((queryEvents[0] as any).prefix).toBe(prefix);
    expect((queryEvents[0] as any).sequenceNumber).toBe(4); // sn - 1
  });

  // ---------------------------------------------------------------------------
  // L12: Replay from scratch
  // ---------------------------------------------------------------------------

  it("L12: replay from scratch produces same final state", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();

    // Build the event chain
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    const rot = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();

    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(rot.said)
      .sequenceNumber(2)
      .build();

    // First pass
    const { processor: p1 } = makeProcessor({ directMode: true });
    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    const rotSiger = await makeSignedSiger(kp2, rot.raw, 0);
    const ixnSiger = await makeSignedSiger(kp2, ixn.raw, 0);

    await p1.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);
    await p1.ingestEvent({ raw: rot.raw, fields: rot.fields }, [rotSiger]);
    await p1.ingestEvent({ raw: ixn.raw, fields: ixn.fields }, [ixnSiger]);

    const state1 = p1.identifiers.get(icp.prefix)!;

    // Second pass (replay)
    const { processor: p2 } = makeProcessor({ directMode: true });
    await p2.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);
    await p2.ingestEvent({ raw: rot.raw, fields: rot.fields }, [rotSiger]);
    await p2.ingestEvent({ raw: ixn.raw, fields: ixn.fields }, [ixnSiger]);

    const state2 = p2.identifiers.get(icp.prefix)!;

    // Both should produce the same final state
    expect(state1.snapshot()).toEqual(state2.snapshot());
  });

  // ---------------------------------------------------------------------------
  // L13: Snapshot -> restore -> continue
  // ---------------------------------------------------------------------------

  it("L13: snapshot -> restore -> continue processing", async () => {
    const { processor: p1 } = makeProcessor({ directMode: true });

    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();

    // Inception + rotation
    const icp = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();
    const icpSiger = await makeSignedSiger(kp1, icp.raw, 0);
    await p1.ingestEvent({ raw: icp.raw, fields: icp.fields }, [icpSiger]);

    const rot = new RotationBuilder(testHashFn)
      .identifier(icp.prefix)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();
    const rotSiger = await makeSignedSiger(kp2, rot.raw, 0);
    await p1.ingestEvent({ raw: rot.raw, fields: rot.fields }, [rotSiger]);

    // Take snapshot
    const state1 = p1.identifiers.get(icp.prefix)!;
    const snap = state1.snapshot();

    // Restore into a new processor
    const { processor: p2, bus: bus2 } = makeProcessor({ directMode: true });
    const restoredState = IdentifierState.fromSnapshot(snap);
    p2.identifiers.set(icp.prefix, restoredState);

    // Continue with interaction at sn=2
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(rot.said)
      .sequenceNumber(2)
      .build();
    const ixnSiger = await makeSignedSiger(kp2, ixn.raw, 0);
    await p2.ingestEvent({ raw: ixn.raw, fields: ixn.fields }, [ixnSiger]);

    const state2 = p2.identifiers.get(icp.prefix)!;
    expect(state2.sequenceNumber).toBe(2);
    expect(state2.latestEventSaid).toBe(ixn.said);
    expect(state2.signingKeys).toEqual([kp2.verferQb64]);

    const events = bus2.drain();
    expect(events.some((e) => e.type === "EventAccepted")).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // L14: CBOR/MsgPack interop (skipped)
  // ---------------------------------------------------------------------------

  it.skip("L14: CBOR/MsgPack interop - JSON only for now", () => {
    // Placeholder for future CBOR/MGPK serialization support
  });
});
