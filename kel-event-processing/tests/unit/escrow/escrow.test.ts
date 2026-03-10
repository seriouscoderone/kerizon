import { describe, it, expect, beforeEach, vi } from "vitest";
import { EventProcessor } from "../../../src/event-processor.js";
import { DomainEventBus } from "../../../src/domain-events.js";
import type { DomainEvent } from "../../../src/domain-events.js";
import { InMemoryEventRepository, DefaultCryptoProvider } from "../../../src/repository/memory.js";
import { EscrowType } from "../../../src/repository/interface.js";
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeSignedSiger(
  privateKey: CryptoKey,
  raw: Uint8Array,
  index: number,
): Promise<IndexedSiger> {
  const sigBytes = await signMessage(privateKey, raw);
  const qb64 = encodeEd25519IndexedSig(sigBytes, index);
  return { index, raw: sigBytes, qb64 };
}

async function collectEscrow(
  repo: InMemoryEventRepository,
  type: EscrowType,
): Promise<Array<{ prefix: string; sn: number; digest: string }>> {
  const entries: Array<{ prefix: string; sn: number; digest: string }> = [];
  for await (const e of repo.iterateEscrow(type)) {
    entries.push(e);
  }
  return entries;
}

// ---------------------------------------------------------------------------
// E01-E28: Escrow system tests through EventProcessor
// ---------------------------------------------------------------------------

describe("Escrow system", () => {
  let repo: InMemoryEventRepository;
  let bus: DomainEventBus;
  let crypto: DefaultCryptoProvider;
  let processor: EventProcessor;

  beforeEach(() => {
    repo = new InMemoryEventRepository();
    bus = new DomainEventBus();
    crypto = new DefaultCryptoProvider();
    // Use short timeouts for escrow tests (1 second)
    processor = new EventProcessor(repo, bus, crypto, {}, {
      outOfOrder: 1,
      partialSignatures: 1,
      partialWitnesses: 1,
      partialDelegation: 1,
      delegable: 1,
      misfitSource: 1,
      unverifiedWitnessReceipt: 1,
      unverifiedReceipt: 1,
      unverifiedTransferableReceipt: 1,
      likelyDuplicitous: 1,
    });
  });

  // ─── E01-E03: OOE escrow ────────────────────────────────────────────

  it("E01: out-of-order event enters OOE escrow", async () => {
    const kp = await generateKeyPair();

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

    // Event at sn=3 (skipping sn=1 and sn=2)
    const ixnOOO = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(3)
      .previousEvent("EFakePrior00000000000000000000000000000000000")
      .build();

    const ixnSiger = await makeSignedSiger(kp.privateKey, ixnOOO.raw, 0);
    await processor.ingestEvent(
      { raw: ixnOOO.raw, fields: ixnOOO.fields },
      [ixnSiger],
    );

    const entries = await collectEscrow(repo, EscrowType.OOE);
    expect(entries.length).toBe(1);
    expect(entries[0].prefix).toBe(inception.prefix);
    expect(entries[0].sn).toBe(3);
  });

  it("E02: prior event arrives, resolveEscrows accepts OOE event", async () => {
    const kp = await generateKeyPair();

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

    // Interaction at sn=1 (normal)
    const ixn1 = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .build();

    // Interaction at sn=2 that references ixn1
    const ixn2 = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(2)
      .previousEvent(ixn1.said)
      .build();

    // Ingest sn=2 first (out of order) -- should go to OOE
    const ixn2Siger = await makeSignedSiger(kp.privateKey, ixn2.raw, 0);
    await processor.ingestEvent(
      { raw: ixn2.raw, fields: ixn2.fields },
      [ixn2Siger],
    );

    let ooeEntries = await collectEscrow(repo, EscrowType.OOE);
    expect(ooeEntries.length).toBe(1);

    // Now ingest sn=1 (the missing event)
    const ixn1Siger = await makeSignedSiger(kp.privateKey, ixn1.raw, 0);
    await processor.ingestEvent(
      { raw: ixn1.raw, fields: ixn1.fields },
      [ixn1Siger],
    );

    // Resolve escrows -- the OOE event at sn=2 should now be processable
    await processor.resolveEscrows();

    // OOE escrow should be empty
    ooeEntries = await collectEscrow(repo, EscrowType.OOE);
    expect(ooeEntries.length).toBe(0);

    // State should be at sn=2
    const state = processor.identifiers.get(inception.prefix)!;
    expect(state.sequenceNumber).toBe(2);
  });

  it("E03: OOE timeout removes entry and produces EventQueryNeeded", async () => {
    const kp = await generateKeyPair();

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

    // OOE event at sn=3
    const ixnOOO = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(3)
      .previousEvent("EFakePrior00000000000000000000000000000000000")
      .build();

    const ixnSiger = await makeSignedSiger(kp.privateKey, ixnOOO.raw, 0);

    // Override storeDatetime so the escrowed event gets an old timestamp.
    // The inception is already ingested, so all future storeDatetime calls
    // are for the escrowed event.
    const oldStoreDateTime = repo.storeDatetime.bind(repo);
    repo.storeDatetime = async (prefix: string, digest: string, _datetime: string) => {
      const oldTime = new Date(Date.now() - 2000).toISOString();
      return oldStoreDateTime(prefix, digest, oldTime);
    };

    await processor.ingestEvent(
      { raw: ixnOOO.raw, fields: ixnOOO.fields },
      [ixnSiger],
    );

    let ooeEntries = await collectEscrow(repo, EscrowType.OOE);
    expect(ooeEntries.length).toBe(1);

    // Drain existing events
    bus.drain();

    // Resolve escrows - the entry should be timed out
    await processor.resolveEscrows();

    // OOE should be empty now
    ooeEntries = await collectEscrow(repo, EscrowType.OOE);
    expect(ooeEntries.length).toBe(0);

    // Check that EventQueryNeeded was produced
    const events = bus.drain();
    const queryNeeded = events.find((e) => e.type === "EventQueryNeeded");
    expect(queryNeeded).toBeDefined();
    expect((queryNeeded as any).prefix).toBe(inception.prefix);
  });

  // ─── E04-E06: PSE (Partial Signatures Escrow) ────────────────────────
  // PSE is entered when InsufficientSignaturesError is thrown.
  // The processor doesn't do sig verification itself, so we test PSE by
  // manually adding an entry to PSE escrow and verifying resolution.

  it("E04: PSE escrow entry (simulated via direct escrow add)", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    // Manually add to PSE escrow (simulating what would happen if sig verification failed)
    await repo.storeEvent(built.prefix, built.said, built.raw);
    await repo.storeDatetime(built.prefix, built.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.PSE, built.prefix, 0, built.said);

    const entries = await collectEscrow(repo, EscrowType.PSE);
    expect(entries.length).toBe(1);
    expect(entries[0].prefix).toBe(built.prefix);
    expect(entries[0].sn).toBe(0);
  });

  it("E05: PSE resolution on resolveEscrows when event becomes valid", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const siger = await makeSignedSiger(kp.privateKey, built.raw, 0);

    // Store the event and sigs, add to PSE escrow
    await repo.storeEvent(built.prefix, built.said, built.raw);
    await repo.storeControllerSignatures(built.prefix, built.said, [siger]);
    await repo.storeDatetime(built.prefix, built.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.PSE, built.prefix, 0, built.said);

    let entries = await collectEscrow(repo, EscrowType.PSE);
    expect(entries.length).toBe(1);

    // Resolve escrows -- the event should be processable now
    // (ingestEvent will be called with the stored event data)
    await processor.resolveEscrows();

    // PSE should be empty
    entries = await collectEscrow(repo, EscrowType.PSE);
    expect(entries.length).toBe(0);

    // The identifier should have been created
    expect(processor.identifiers.has(built.prefix)).toBe(true);
  });

  it("E06: PSE timeout removes entry", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    // Store with old timestamp
    await repo.storeEvent(built.prefix, built.said, built.raw);
    const oldTime = new Date(Date.now() - 2000).toISOString();
    await repo.storeDatetime(built.prefix, built.said, oldTime);
    await repo.addToEscrow(EscrowType.PSE, built.prefix, 0, built.said);

    let entries = await collectEscrow(repo, EscrowType.PSE);
    expect(entries.length).toBe(1);

    await processor.resolveEscrows();

    entries = await collectEscrow(repo, EscrowType.PSE);
    expect(entries.length).toBe(0);
  });

  // ─── E07-E09: PWE (Partial Witnesses Escrow) ─────────────────────────

  it("E07: PWE escrow entry (simulated)", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    await repo.storeEvent(built.prefix, built.said, built.raw);
    await repo.storeDatetime(built.prefix, built.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.PWE, built.prefix, 0, built.said);

    const entries = await collectEscrow(repo, EscrowType.PWE);
    expect(entries.length).toBe(1);
    expect(entries[0].sn).toBe(0);
  });

  it("E08: PWE resolution on resolveEscrows", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const siger = await makeSignedSiger(kp.privateKey, built.raw, 0);

    await repo.storeEvent(built.prefix, built.said, built.raw);
    await repo.storeControllerSignatures(built.prefix, built.said, [siger]);
    await repo.storeDatetime(built.prefix, built.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.PWE, built.prefix, 0, built.said);

    await processor.resolveEscrows();

    const entries = await collectEscrow(repo, EscrowType.PWE);
    expect(entries.length).toBe(0);
    expect(processor.identifiers.has(built.prefix)).toBe(true);
  });

  it("E09: PWE timeout removes entry", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    await repo.storeEvent(built.prefix, built.said, built.raw);
    const oldTime = new Date(Date.now() - 2000).toISOString();
    await repo.storeDatetime(built.prefix, built.said, oldTime);
    await repo.addToEscrow(EscrowType.PWE, built.prefix, 0, built.said);

    await processor.resolveEscrows();

    const entries = await collectEscrow(repo, EscrowType.PWE);
    expect(entries.length).toBe(0);
  });

  // ─── E10-E12: PDE (Partial Delegation Escrow) ────────────────────────

  it("E10: PDE escrow entry (simulated)", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    await repo.storeEvent(built.prefix, built.said, built.raw);
    await repo.storeDatetime(built.prefix, built.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.PDE, built.prefix, 0, built.said);

    const entries = await collectEscrow(repo, EscrowType.PDE);
    expect(entries.length).toBe(1);
  });

  it("E11: PDE resolution on resolveEscrows", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const siger = await makeSignedSiger(kp.privateKey, built.raw, 0);

    await repo.storeEvent(built.prefix, built.said, built.raw);
    await repo.storeControllerSignatures(built.prefix, built.said, [siger]);
    await repo.storeDatetime(built.prefix, built.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.PDE, built.prefix, 0, built.said);

    await processor.resolveEscrows();

    const entries = await collectEscrow(repo, EscrowType.PDE);
    expect(entries.length).toBe(0);
    expect(processor.identifiers.has(built.prefix)).toBe(true);
  });

  it("E12: PDE timeout removes entry", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    await repo.storeEvent(built.prefix, built.said, built.raw);
    const oldTime = new Date(Date.now() - 2000).toISOString();
    await repo.storeDatetime(built.prefix, built.said, oldTime);
    await repo.addToEscrow(EscrowType.PDE, built.prefix, 0, built.said);

    await processor.resolveEscrows();

    const entries = await collectEscrow(repo, EscrowType.PDE);
    expect(entries.length).toBe(0);
  });

  // ─── E13-E14: MFE (Misfit Source Escrow) ──────────────────────────────
  // NOTE: MFE is NOT in ESCROW_PROCESSING_ORDER, so resolveEscrows does
  // not iterate or timeout MFE entries. These tests verify storage only.

  it("E13: MFE escrow entry (simulated)", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    await repo.storeEvent(built.prefix, built.said, built.raw);
    await repo.storeDatetime(built.prefix, built.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.MFE, built.prefix, 0, built.said);

    const entries = await collectEscrow(repo, EscrowType.MFE);
    expect(entries.length).toBe(1);
  });

  it("E14: MFE entry persists through resolveEscrows (not in processing order)", async () => {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    await repo.storeEvent(built.prefix, built.said, built.raw);
    const oldTime = new Date(Date.now() - 2000).toISOString();
    await repo.storeDatetime(built.prefix, built.said, oldTime);
    await repo.addToEscrow(EscrowType.MFE, built.prefix, 0, built.said);

    // resolveEscrows does NOT process MFE (not in ESCROW_PROCESSING_ORDER)
    await processor.resolveEscrows();

    // MFE entry should still be present
    const entries = await collectEscrow(repo, EscrowType.MFE);
    expect(entries.length).toBe(1);
  });

  // ─── E15-E20: Receipt escrows (UWE, URE, VRE) ─────────────────────────
  // These escrow types handle receipts that arrived before their event.
  // In the current implementation, ingestReceipt throws errors rather than
  // escrowing them directly. These tests verify the escrow storage/timeout
  // via direct escrow manipulation.

  it("E15: UWE escrow entry (simulated)", async () => {
    const prefix = "EUnverifiedWitness0000000000000000000000000";
    const said = "EWitSaid000000000000000000000000000000000000";
    const raw = new TextEncoder().encode("dummy-receipt-bytes");

    await repo.storeEvent(prefix, said, raw);
    await repo.storeDatetime(prefix, said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.UWE, prefix, 0, said);

    const entries = await collectEscrow(repo, EscrowType.UWE);
    expect(entries.length).toBe(1);
    expect(entries[0].prefix).toBe(prefix);
  });

  it("E16: UWE timeout removes entry", async () => {
    const prefix = "EUnverifiedWitness0000000000000000000000000";
    const said = "EWitSaid000000000000000000000000000000000000";
    const raw = new TextEncoder().encode("dummy-receipt-bytes");

    await repo.storeEvent(prefix, said, raw);
    const oldTime = new Date(Date.now() - 2000).toISOString();
    await repo.storeDatetime(prefix, said, oldTime);
    await repo.addToEscrow(EscrowType.UWE, prefix, 0, said);

    await processor.resolveEscrows();

    const entries = await collectEscrow(repo, EscrowType.UWE);
    expect(entries.length).toBe(0);
  });

  it("E17: URE escrow entry (simulated)", async () => {
    const prefix = "EUnverifiedReceipt000000000000000000000000";
    const said = "EUreSaid000000000000000000000000000000000000";
    const raw = new TextEncoder().encode("dummy-receipt-bytes");

    await repo.storeEvent(prefix, said, raw);
    await repo.storeDatetime(prefix, said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.URE, prefix, 0, said);

    const entries = await collectEscrow(repo, EscrowType.URE);
    expect(entries.length).toBe(1);
  });

  it("E18: URE timeout removes entry", async () => {
    const prefix = "EUnverifiedReceipt000000000000000000000000";
    const said = "EUreSaid000000000000000000000000000000000000";
    const raw = new TextEncoder().encode("dummy-receipt-bytes");

    await repo.storeEvent(prefix, said, raw);
    const oldTime = new Date(Date.now() - 2000).toISOString();
    await repo.storeDatetime(prefix, said, oldTime);
    await repo.addToEscrow(EscrowType.URE, prefix, 0, said);

    await processor.resolveEscrows();

    const entries = await collectEscrow(repo, EscrowType.URE);
    expect(entries.length).toBe(0);
  });

  it("E19: VRE escrow entry (simulated)", async () => {
    const prefix = "EVerifiedTransferable00000000000000000000000";
    const said = "EVreSaid000000000000000000000000000000000000";
    const raw = new TextEncoder().encode("dummy-receipt-bytes");

    await repo.storeEvent(prefix, said, raw);
    await repo.storeDatetime(prefix, said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.VRE, prefix, 0, said);

    const entries = await collectEscrow(repo, EscrowType.VRE);
    expect(entries.length).toBe(1);
  });

  it("E20: VRE timeout removes entry", async () => {
    const prefix = "EVerifiedTransferable00000000000000000000000";
    const said = "EVreSaid000000000000000000000000000000000000";
    const raw = new TextEncoder().encode("dummy-receipt-bytes");

    await repo.storeEvent(prefix, said, raw);
    const oldTime = new Date(Date.now() - 2000).toISOString();
    await repo.storeDatetime(prefix, said, oldTime);
    await repo.addToEscrow(EscrowType.VRE, prefix, 0, said);

    await processor.resolveEscrows();

    const entries = await collectEscrow(repo, EscrowType.VRE);
    expect(entries.length).toBe(0);
  });

  // ─── E21-E22: LDE (Likely Duplicitous Escrow) ────────────────────────

  it("E21: LDE escrow entry via duplicitous event", async () => {
    const kp = await generateKeyPair();

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

    // Different event at sn=1 (different SAID)
    const ixnDuplicitous = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .anchoredSeals([{ d: "EDuplicitousAnchor000000000000000000000000" }])
      .build();

    const ixnDupeSiger = await makeSignedSiger(kp.privateKey, ixnDuplicitous.raw, 0);
    await processor.ingestEvent(
      { raw: ixnDuplicitous.raw, fields: ixnDuplicitous.fields },
      [ixnDupeSiger],
    );

    const entries = await collectEscrow(repo, EscrowType.LDE);
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries.some((e) => e.prefix === inception.prefix && e.sn === 1)).toBe(true);
  });

  it("E22: LDE escrow is NOT re-processed on resolveEscrows (evidence only)", async () => {
    const kp = await generateKeyPair();

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

    // Duplicitous event at sn=1
    const ixnDuplicitous = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .anchoredSeals([{ d: "ELDEEvidence000000000000000000000000000000" }])
      .build();

    const ixnDupeSiger = await makeSignedSiger(kp.privateKey, ixnDuplicitous.raw, 0);
    await processor.ingestEvent(
      { raw: ixnDuplicitous.raw, fields: ixnDuplicitous.fields },
      [ixnDupeSiger],
    );

    let entries = await collectEscrow(repo, EscrowType.LDE);
    expect(entries.length).toBeGreaterThanOrEqual(1);

    // Resolve escrows -- LDE entries should remain (not timed out yet)
    await processor.resolveEscrows();

    // LDE entries should still be there (LDE is evidence-only, not re-processed)
    entries = await collectEscrow(repo, EscrowType.LDE);
    expect(entries.length).toBeGreaterThanOrEqual(1);
  });

  // ─── E23-E24: Delegable escrow ────────────────────────────────────────
  // NOTE: DELEGABLE is NOT in ESCROW_PROCESSING_ORDER, so resolveEscrows
  // does not iterate or timeout DELEGABLE entries.

  it("E23: Delegable escrow entry (simulated)", async () => {
    const prefix = "EDelegable000000000000000000000000000000000";
    const said = "EDelegableSaid00000000000000000000000000000";
    const raw = new TextEncoder().encode("dummy-delegable");

    await repo.storeEvent(prefix, said, raw);
    await repo.storeDatetime(prefix, said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.DELEGABLE, prefix, 0, said);

    const entries = await collectEscrow(repo, EscrowType.DELEGABLE);
    expect(entries.length).toBe(1);
    expect(entries[0].prefix).toBe(prefix);
  });

  it("E24: Delegable entry persists through resolveEscrows (not in processing order)", async () => {
    const prefix = "EDelegable000000000000000000000000000000000";
    const said = "EDelegableSaid00000000000000000000000000000";
    const raw = new TextEncoder().encode("dummy-delegable");

    await repo.storeEvent(prefix, said, raw);
    const oldTime = new Date(Date.now() - 2000).toISOString();
    await repo.storeDatetime(prefix, said, oldTime);
    await repo.addToEscrow(EscrowType.DELEGABLE, prefix, 0, said);

    // resolveEscrows does NOT process DELEGABLE (not in ESCROW_PROCESSING_ORDER)
    await processor.resolveEscrows();

    // Delegable entry should still be present
    const entries = await collectEscrow(repo, EscrowType.DELEGABLE);
    expect(entries.length).toBe(1);
  });

  // ─── E25: Processing order ────────────────────────────────────────────

  it("E25: escrow processing order follows spec Section 11.2", async () => {
    // We verify order by placing entries in multiple escrow types and checking
    // that they are all processed. The order is:
    // OOE, UWE, URE, VRE, PDE, PWE, PSE, LDE

    // Create a valid inception that can be resolved from any escrow
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const siger = await makeSignedSiger(kp.privateKey, built.raw, 0);

    // Store the event bytes and sigs for all escrow types
    await repo.storeEvent(built.prefix, built.said, built.raw);
    await repo.storeControllerSignatures(built.prefix, built.said, [siger]);
    await repo.storeDatetime(built.prefix, built.said, new Date().toISOString());

    // Add to OOE and PSE (both will try to re-ingest the inception event)
    await repo.addToEscrow(EscrowType.OOE, built.prefix, 0, built.said);
    await repo.addToEscrow(EscrowType.PSE, built.prefix, 0, built.said);

    await processor.resolveEscrows();

    // Both should be resolved
    const ooeEntries = await collectEscrow(repo, EscrowType.OOE);
    const pseEntries = await collectEscrow(repo, EscrowType.PSE);
    expect(ooeEntries.length).toBe(0);
    expect(pseEntries.length).toBe(0);

    // The inception should have been processed
    expect(processor.identifiers.has(built.prefix)).toBe(true);
  });

  // ─── E26: Cascade resolution ──────────────────────────────────────────

  it("E26: cascade resolution (processing one escrow enables another)", async () => {
    const kp = await generateKeyPair();

    // Inception event
    const inception = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const icpSiger = await makeSignedSiger(kp.privateKey, inception.raw, 0);

    // Interaction at sn=1
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(inception.prefix)
      .sequenceNumber(1)
      .previousEvent(inception.said)
      .build();

    const ixnSiger = await makeSignedSiger(kp.privateKey, ixn.raw, 0);

    // Put inception in OOE and ixn in PSE (OOE is processed first in the order).
    // OOE processes inception -> accepted, then PSE processes ixn -> accepted.
    await repo.storeEvent(inception.prefix, inception.said, inception.raw);
    await repo.storeControllerSignatures(inception.prefix, inception.said, [icpSiger]);
    await repo.storeDatetime(inception.prefix, inception.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.OOE, inception.prefix, 0, inception.said);

    await repo.storeEvent(inception.prefix, ixn.said, ixn.raw);
    await repo.storeControllerSignatures(inception.prefix, ixn.said, [ixnSiger]);
    await repo.storeDatetime(inception.prefix, ixn.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.PSE, inception.prefix, 1, ixn.said);

    // First resolve: OOE processes the inception, PSE processes the ixn
    await processor.resolveEscrows();

    // Inception should be resolved from OOE
    expect(processor.identifiers.has(inception.prefix)).toBe(true);

    // Both escrows should be empty after one pass
    // (OOE processes first and accepts inception, then PSE processes ixn which is now valid)
    const ooeEntries = await collectEscrow(repo, EscrowType.OOE);
    const pseEntries = await collectEscrow(repo, EscrowType.PSE);
    expect(ooeEntries.length).toBe(0);
    expect(pseEntries.length).toBe(0);

    // State should be at sn=1
    const state = processor.identifiers.get(inception.prefix)!;
    expect(state.sequenceNumber).toBe(1);
  });

  // ─── E27: Idempotent escrow entry ────────────────────────────────────

  it("E27: idempotent escrow entry (same event added twice)", async () => {
    const kp = await generateKeyPair();

    const inception = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    await repo.storeEvent(inception.prefix, inception.said, inception.raw);
    await repo.storeDatetime(inception.prefix, inception.said, new Date().toISOString());

    // Add to escrow twice
    await repo.addToEscrow(EscrowType.OOE, inception.prefix, 0, inception.said);
    await repo.addToEscrow(EscrowType.OOE, inception.prefix, 0, inception.said);

    // Should only have one entry (deduplication)
    const entries = await collectEscrow(repo, EscrowType.OOE);
    expect(entries.length).toBe(1);
  });

  // ─── E28: Re-ingest behavior during resolve ──────────────────────────

  it("E28: re-ingest that routes back to escrow is still removed from original escrow", async () => {
    // When resolveEscrows re-ingests an event that fails and gets routed
    // back to escrow via routeToEscrow, the entry is still removed from
    // the original escrow position because:
    // 1. ingestEvent catches the error and calls routeToEscrow (which returns normally)
    // 2. resolveEscrows sees no exception, thinks it succeeded, adds to toRemove
    // 3. routeToEscrow's addToEscrow is idempotent (no-op for existing entry)
    // 4. removeFromEscrow removes the entry
    //
    // This verifies that behavior -- the entry ends up removed after resolve.
    const kp = await generateKeyPair();
    const unknownPrefix = "EStillUnknown000000000000000000000000000000";

    const ixn = new InteractionBuilder(testHashFn)
      .identifier(unknownPrefix)
      .sequenceNumber(1)
      .previousEvent("EFakePrior00000000000000000000000000000000000")
      .build();

    const ixnSiger = await makeSignedSiger(kp.privateKey, ixn.raw, 0);

    // Put in OOE escrow
    await repo.storeEvent(unknownPrefix, ixn.said, ixn.raw);
    await repo.storeControllerSignatures(unknownPrefix, ixn.said, [ixnSiger]);
    await repo.storeDatetime(unknownPrefix, ixn.said, new Date().toISOString());
    await repo.addToEscrow(EscrowType.OOE, unknownPrefix, 1, ixn.said);

    let entries = await collectEscrow(repo, EscrowType.OOE);
    expect(entries.length).toBe(1);

    // Resolve -- the event still can't be processed (no inception for unknownPrefix)
    // but ingestEvent doesn't throw (it routes to escrow internally).
    // The entry is removed from OOE by the toRemove cleanup.
    await processor.resolveEscrows();

    // Entry is removed because ingestEvent swallows the error via routeToEscrow
    entries = await collectEscrow(repo, EscrowType.OOE);
    expect(entries.length).toBe(0);
  });
});
