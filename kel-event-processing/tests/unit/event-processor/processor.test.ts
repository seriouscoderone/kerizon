import { describe, it, expect, beforeEach } from "vitest";
import { EventProcessor } from "../../../src/event-processor.js";
import { DomainEventBus } from "../../../src/domain-events.js";
import { InMemoryEventRepository, DefaultCryptoProvider } from "../../../src/repository/memory.js";
import { EscrowType } from "../../../src/repository/interface.js";
import { IdentifierState } from "../../../src/identifier-state.js";
import {
  generateKeyPair,
  signMessage,
  testHashFn,
  encodeEd25519IndexedSig,
} from "../../helpers.js";
import { InceptionBuilder } from "../../../src/builders/inception.js";
import { RotationBuilder } from "../../../src/builders/rotation.js";
import { InteractionBuilder } from "../../../src/builders/interaction.js";
import type { IndexedSiger } from "../../../src/verification.js";
import type { DomainEvent } from "../../../src/domain-events.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeKeyPair() {
  return generateKeyPair();
}

async function makeSignedSiger(
  privateKey: CryptoKey,
  raw: Uint8Array,
  index: number,
): Promise<IndexedSiger> {
  const sigBytes = await signMessage(privateKey, raw);
  const qb64 = encodeEd25519IndexedSig(sigBytes, index);
  return { index, raw: sigBytes, qb64 };
}

// ---------------------------------------------------------------------------
// P01-P11: EventProcessor tests
// ---------------------------------------------------------------------------

describe("EventProcessor", () => {
  let repo: InMemoryEventRepository;
  let bus: DomainEventBus;
  let crypto: DefaultCryptoProvider;
  let processor: EventProcessor;

  beforeEach(() => {
    repo = new InMemoryEventRepository();
    bus = new DomainEventBus();
    crypto = new DefaultCryptoProvider();
    processor = new EventProcessor(repo, bus, crypto);
  });

  it("P01: ingest valid inception creates IdentifierState", async () => {
    const kp = await makeKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const siger = await makeSignedSiger(kp.privateKey, built.raw, 0);

    await processor.ingestEvent(
      { raw: built.raw, fields: built.fields },
      [siger],
    );

    // The identifier should now be in the processor's identifiers map
    expect(processor.identifiers.has(built.prefix)).toBe(true);
    const state = processor.identifiers.get(built.prefix)!;
    expect(state.prefix).toBe(built.prefix);
    expect(state.sequenceNumber).toBe(0);
    expect(state.signingKeys).toEqual([kp.verferQb64]);
  });

  it("P02: ingest inception produces EventAccepted domain event (direct mode)", async () => {
    const kp = await makeKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const siger = await makeSignedSiger(kp.privateKey, built.raw, 0);

    await processor.ingestEvent(
      { raw: built.raw, fields: built.fields },
      [siger],
    );

    const events = bus.drain();
    expect(events.length).toBeGreaterThanOrEqual(1);
    const accepted = events.find((e) => e.type === "EventAccepted");
    expect(accepted).toBeDefined();
    expect(accepted!.type).toBe("EventAccepted");
    expect((accepted as any).prefix).toBe(built.prefix);
    expect((accepted as any).sn).toBe(0);
    expect((accepted as any).said).toBe(built.said);
  });

  it("P03: ingest rotation after inception updates state to sn=1", async () => {
    const kp = await makeKeyPair();
    const kp2 = await makeKeyPair();

    // Inception
    const inception = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp.privateKey, inception.raw, 0);
    await processor.ingestEvent(
      { raw: inception.raw, fields: inception.fields },
      [icpSiger],
    );

    // Rotation
    const rotation = new RotationBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    const rotSiger = await makeSignedSiger(kp2.privateKey, rotation.raw, 0);
    await processor.ingestEvent(
      { raw: rotation.raw, fields: rotation.fields },
      [rotSiger],
    );

    const state = processor.identifiers.get(inception.prefix)!;
    expect(state.sequenceNumber).toBe(1);
    expect(state.signingKeys).toEqual([kp2.verferQb64]);
  });

  it("P04: ingest interaction after inception updates state, keys unchanged", async () => {
    const kp = await makeKeyPair();

    // Inception
    const inception = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp.privateKey, inception.raw, 0);
    await processor.ingestEvent(
      { raw: inception.raw, fields: inception.fields },
      [icpSiger],
    );

    // Interaction
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .build();

    const ixnSiger = await makeSignedSiger(kp.privateKey, ixn.raw, 0);
    await processor.ingestEvent(
      { raw: ixn.raw, fields: ixn.fields },
      [ixnSiger],
    );

    const state = processor.identifiers.get(inception.prefix)!;
    expect(state.sequenceNumber).toBe(1);
    // Keys should not change after interaction
    expect(state.signingKeys).toEqual([kp.verferQb64]);
  });

  it("P05: duplicate inception same SAID is idempotent (accumulate sigs, no error)", async () => {
    const kp = await makeKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const siger = await makeSignedSiger(kp.privateKey, built.raw, 0);

    // Ingest first time
    await processor.ingestEvent(
      { raw: built.raw, fields: built.fields },
      [siger],
    );

    // Ingest same event again (duplicate) - should not throw
    await processor.ingestEvent(
      { raw: built.raw, fields: built.fields },
      [siger],
    );

    // State should still be at sn=0
    const state = processor.identifiers.get(built.prefix)!;
    expect(state.sequenceNumber).toBe(0);
    expect(state.latestEventSaid).toBe(built.said);
  });

  it("P06: different inception at sn=0 routes to LDE escrow", async () => {
    const kp1 = await makeKeyPair();
    const kp2 = await makeKeyPair();

    // First inception
    const inception1 = new InceptionBuilder(testHashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp1.verferQb64])
      .build();

    const siger1 = await makeSignedSiger(kp1.privateKey, inception1.raw, 0);
    await processor.ingestEvent(
      { raw: inception1.raw, fields: inception1.fields },
      [siger1],
    );

    // Second (different) inception for the same prefix -- we must fabricate
    // an inception with the same prefix (i field) but different SAID (d field).
    // Since inception prefix == SAID, a truly different inception will have a different
    // prefix. So we fabricate fields with the same i but different d.
    const prefix = inception1.prefix;
    const said1 = inception1.said;

    // Build a second inception with a different key (will have a different SAID/prefix)
    const inception2 = new InceptionBuilder(testHashFn)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    // Override the fields to have the same prefix but keep the different SAID
    const fakeFields = { ...inception2.fields, i: prefix };
    const fakeRaw = new TextEncoder().encode(JSON.stringify(fakeFields));
    const siger2 = await makeSignedSiger(kp2.privateKey, fakeRaw, 0);

    // This should route to LDE escrow (DuplicitousEventError caught internally)
    await processor.ingestEvent(
      { raw: fakeRaw, fields: fakeFields },
      [siger2],
    );

    // Check LDE escrow has an entry
    const entries: Array<{ prefix: string; sn: number; digest: string }> = [];
    for await (const e of repo.iterateEscrow(EscrowType.LDE)) {
      entries.push(e);
    }
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries.some((e) => e.prefix === prefix && e.sn === 0)).toBe(true);
  });

  it("P07: different event at same sn routes to LDE escrow", async () => {
    const kp = await makeKeyPair();

    // Inception
    const inception = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp.privateKey, inception.raw, 0);
    await processor.ingestEvent(
      { raw: inception.raw, fields: inception.fields },
      [icpSiger],
    );

    // Interaction at sn=1
    const ixn1 = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .build();

    const ixn1Siger = await makeSignedSiger(kp.privateKey, ixn1.raw, 0);
    await processor.ingestEvent(
      { raw: ixn1.raw, fields: ixn1.fields },
      [ixn1Siger],
    );

    // Now try a DIFFERENT interaction at sn=1 (different anchors/seals to get different SAID)
    const ixn2 = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .anchoredSeals([{ d: "EFakeDigest000000000000000000000000000000000" }])
      .build();

    const ixn2Siger = await makeSignedSiger(kp.privateKey, ixn2.raw, 0);
    // The sn=1 < current sn+1=2, and existing digest != this SAID, so it should be
    // caught as DuplicitousEventError and routed to LDE
    await processor.ingestEvent(
      { raw: ixn2.raw, fields: ixn2.fields },
      [ixn2Siger],
    );

    // Check LDE escrow
    const entries: Array<{ prefix: string; sn: number; digest: string }> = [];
    for await (const e of repo.iterateEscrow(EscrowType.LDE)) {
      entries.push(e);
    }
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries.some((e) => e.prefix === inception.prefix && e.sn === 1)).toBe(true);
  });

  it("P08: event with sn > current+1 routes to OOE escrow", async () => {
    const kp = await makeKeyPair();

    // Inception
    const inception = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp.privateKey, inception.raw, 0);
    await processor.ingestEvent(
      { raw: inception.raw, fields: inception.fields },
      [icpSiger],
    );

    // Skip sn=1, go straight to sn=3
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(3)
      .previousEvent("EFakePrior00000000000000000000000000000000000")
      .build();

    const ixnSiger = await makeSignedSiger(kp.privateKey, ixn.raw, 0);
    await processor.ingestEvent(
      { raw: ixn.raw, fields: ixn.fields },
      [ixnSiger],
    );

    // Check OOE escrow
    const entries: Array<{ prefix: string; sn: number; digest: string }> = [];
    for await (const e of repo.iterateEscrow(EscrowType.OOE)) {
      entries.push(e);
    }
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries.some((e) => e.prefix === inception.prefix && e.sn === 3)).toBe(true);
  });

  it("P09: non-inception for unknown prefix routes to OOE escrow", async () => {
    const kp = await makeKeyPair();
    const unknownPrefix = "EUnknownPrefix000000000000000000000000000000";

    const ixn = new InteractionBuilder(testHashFn)
      .identifier(unknownPrefix)
      .sequenceNumber(1)
      .previousEvent("EFakePrior00000000000000000000000000000000000")
      .build();

    const ixnSiger = await makeSignedSiger(kp.privateKey, ixn.raw, 0);
    await processor.ingestEvent(
      { raw: ixn.raw, fields: ixn.fields },
      [ixnSiger],
    );

    // Check OOE escrow
    const entries: Array<{ prefix: string; sn: number; digest: string }> = [];
    for await (const e of repo.iterateEscrow(EscrowType.OOE)) {
      entries.push(e);
    }
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries.some((e) => e.prefix === unknownPrefix)).toBe(true);
  });

  it("P10: event at sn <= current (not recovery) routes to LDE escrow", async () => {
    const kp = await makeKeyPair();

    // Inception
    const inception = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp.privateKey, inception.raw, 0);
    await processor.ingestEvent(
      { raw: inception.raw, fields: inception.fields },
      [icpSiger],
    );

    // Interaction at sn=1
    const ixn1 = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .build();

    const ixn1Siger = await makeSignedSiger(kp.privateKey, ixn1.raw, 0);
    await processor.ingestEvent(
      { raw: ixn1.raw, fields: ixn1.fields },
      [ixn1Siger],
    );

    // Interaction at sn=2
    const ixn2 = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(2)
      .previousEvent(ixn1.said)
      .build();

    const ixn2Siger = await makeSignedSiger(kp.privateKey, ixn2.raw, 0);
    await processor.ingestEvent(
      { raw: ixn2.raw, fields: ixn2.fields },
      [ixn2Siger],
    );

    // Now try a DIFFERENT interaction at sn=1 (different SAID)
    const ixnDupe = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .anchoredSeals([{ d: "EDuplicateAnchor0000000000000000000000000000" }])
      .build();

    const ixnDupeSiger = await makeSignedSiger(kp.privateKey, ixnDupe.raw, 0);
    await processor.ingestEvent(
      { raw: ixnDupe.raw, fields: ixnDupe.fields },
      [ixnDupeSiger],
    );

    // Check LDE escrow has the duplicate
    const entries: Array<{ prefix: string; sn: number; digest: string }> = [];
    for await (const e of repo.iterateEscrow(EscrowType.LDE)) {
      entries.push(e);
    }
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries.some((e) => e.prefix === inception.prefix && e.sn === 1)).toBe(true);
  });

  it("P11: recovery rotation superseding prior interaction is accepted", async () => {
    const kp = await makeKeyPair();
    const kp2 = await makeKeyPair();

    // Inception
    const inception = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp.privateKey, inception.raw, 0);
    await processor.ingestEvent(
      { raw: inception.raw, fields: inception.fields },
      [icpSiger],
    );

    // Interaction at sn=1
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .build();

    const ixnSiger = await makeSignedSiger(kp.privateKey, ixn.raw, 0);
    await processor.ingestEvent(
      { raw: ixn.raw, fields: ixn.fields },
      [ixnSiger],
    );

    expect(processor.identifiers.get(inception.prefix)!.sequenceNumber).toBe(1);

    // Recovery rotation at sn=1 (lastEstSn=0 < sn=1 <= currentSn=1) - valid recovery
    const kp3 = await makeKeyPair();
    const recoveryRot = new RotationBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .build();

    const recoverySiger = await makeSignedSiger(kp2.privateKey, recoveryRot.raw, 0);
    await processor.ingestEvent(
      { raw: recoveryRot.raw, fields: recoveryRot.fields },
      [recoverySiger],
    );

    // The state should now reflect the recovery rotation
    const state = processor.identifiers.get(inception.prefix)!;
    expect(state.sequenceNumber).toBe(1);
    expect(state.signingKeys).toEqual([kp2.verferQb64]);
    expect(state.eventIlk).toBe("rot");

    // Should have produced an EventAccepted for the recovery
    const domainEvents = bus.drain();
    const accepted = domainEvents.filter((e) => e.type === "EventAccepted");
    // Should have at least inception + ixn + recovery = 3 events
    // (but we already drained inception and ixn in earlier calls, so the bus only has
    //  what accumulated since the last drain; since we never drained before, all 3 are here)
    expect(accepted.length).toBe(3);
  });
});
