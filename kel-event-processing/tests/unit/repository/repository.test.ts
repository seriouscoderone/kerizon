import { describe, it, expect } from "vitest";
import { InMemoryEventRepository } from "../../../src/repository/memory.js";
import { EscrowType } from "../../../src/repository/interface.js";
import type { IndexedSiger } from "../../../src/verification.js";
import type { KeyStateSnapshot, EventProvenance } from "../../../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRepo() {
  return new InMemoryEventRepository();
}

function makeSiger(index: number, label?: string): IndexedSiger {
  const raw = new Uint8Array(64);
  raw[0] = index;
  raw[1] = label ? label.charCodeAt(0) : 0;
  return {
    index,
    raw,
    qb64: `sig_${index}_${label ?? "default"}`,
  };
}

function fakeSnapshot(overrides: Partial<KeyStateSnapshot> = {}): KeyStateSnapshot {
  return {
    vn: [1, 0],
    i: "ESnapshotPrefix00000000000000000000000000000",
    s: "0",
    p: "",
    d: "ESnapshotDigest00000000000000000000000000000",
    f: "0",
    dt: "2026-03-10T00:00:00.000000+00:00",
    et: "icp",
    kt: "1",
    k: ["DKey111111111111111111111111111111111111111"],
    nt: "1",
    n: ["ENext11111111111111111111111111111111111111"],
    bt: "0",
    b: [],
    c: [],
    ee: { s: "0", d: "ESnapshotDigest00000000000000000000000000000", br: [], ba: [] },
    di: "",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// RP01: storeEvent + retrieveEvent roundtrip
// ---------------------------------------------------------------------------

describe("InMemoryEventRepository", () => {
  it("RP01: storeEvent + retrieveEvent matches", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";
    const eventBytes = new TextEncoder().encode('{"t":"icp","i":"EPrefix0000000000000000000000000000000000000"}');

    await repo.storeEvent(prefix, digest, eventBytes);
    const retrieved = await repo.retrieveEvent(prefix, digest);

    expect(retrieved).toBeDefined();
    expect(retrieved).toEqual(eventBytes);
  });

  // ---------------------------------------------------------------------------
  // RP02: Store same event twice -> no error, same result
  // ---------------------------------------------------------------------------

  it("RP02: store same event twice -> no error, same result", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";
    const eventBytes = new TextEncoder().encode('{"t":"icp"}');

    await repo.storeEvent(prefix, digest, eventBytes);
    await repo.storeEvent(prefix, digest, eventBytes);

    const retrieved = await repo.retrieveEvent(prefix, digest);
    expect(retrieved).toEqual(eventBytes);
  });

  // ---------------------------------------------------------------------------
  // RP03: Retrieve non-existent -> undefined
  // ---------------------------------------------------------------------------

  it("RP03: retrieve non-existent event -> undefined", async () => {
    const repo = makeRepo();
    const result = await repo.retrieveEvent("ENonExist0000000000000000000000000000000000", "ENone00000000000000000000000000000000000000");
    expect(result).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // RP04: appendToEventLog -> getLastEventDigest returns last
  // ---------------------------------------------------------------------------

  it("RP04: appendToEventLog multiple -> getLastEventDigest returns last", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";

    await repo.appendToEventLog(prefix, 0, "EDigest_0_A");
    await repo.appendToEventLog(prefix, 1, "EDigest_1_A");
    await repo.appendToEventLog(prefix, 2, "EDigest_2_A");

    expect(await repo.getLastEventDigest(prefix, 0)).toBe("EDigest_0_A");
    expect(await repo.getLastEventDigest(prefix, 1)).toBe("EDigest_1_A");
    expect(await repo.getLastEventDigest(prefix, 2)).toBe("EDigest_2_A");
    expect(await repo.getLastEventDigest(prefix, 3)).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // RP05: iterateEventLogBackward -> reverse sn order
  // ---------------------------------------------------------------------------

  it("RP05: iterateEventLogBackward -> reverse sn order", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";

    await repo.appendToEventLog(prefix, 0, "D0");
    await repo.appendToEventLog(prefix, 1, "D1");
    await repo.appendToEventLog(prefix, 2, "D2");
    await repo.appendToEventLog(prefix, 3, "D3");

    const entries: Array<{ sn: number; digest: string }> = [];
    for await (const entry of repo.iterateEventLogBackward(prefix)) {
      entries.push(entry);
    }

    expect(entries).toHaveLength(4);
    // Must be in descending sn order
    expect(entries[0].sn).toBe(3);
    expect(entries[1].sn).toBe(2);
    expect(entries[2].sn).toBe(1);
    expect(entries[3].sn).toBe(0);
    expect(entries[0].digest).toBe("D3");
    expect(entries[3].digest).toBe("D0");
  });

  // ---------------------------------------------------------------------------
  // RP06: appendToFirstSeenLog -> monotonically increasing ordinals
  // ---------------------------------------------------------------------------

  it("RP06: appendToFirstSeenLog -> monotonically increasing ordinals", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";

    const fn0 = await repo.appendToFirstSeenLog(prefix, "D0");
    const fn1 = await repo.appendToFirstSeenLog(prefix, "D1");
    const fn2 = await repo.appendToFirstSeenLog(prefix, "D2");

    expect(fn0).toBe(0);
    expect(fn1).toBe(1);
    expect(fn2).toBe(2);
    // Monotonically increasing
    expect(fn1).toBeGreaterThan(fn0);
    expect(fn2).toBeGreaterThan(fn1);
  });

  // ---------------------------------------------------------------------------
  // RP07: storeFirstSeenOrdinal + getFirstSeenOrdinal roundtrip
  // ---------------------------------------------------------------------------

  it("RP07: storeFirstSeenOrdinal + getFirstSeenOrdinal matches", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";

    await repo.storeFirstSeenOrdinal(prefix, digest, 42);
    const result = await repo.getFirstSeenOrdinal(prefix, digest);

    expect(result).toBe(42);

    // Non-existent
    const missing = await repo.getFirstSeenOrdinal(prefix, "ENone");
    expect(missing).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // RP08: storeControllerSignatures accumulation (union of sigs)
  // ---------------------------------------------------------------------------

  it("RP08: storeControllerSignatures accumulation -> union of sigs", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";

    const sig0 = makeSiger(0, "a");
    const sig1 = makeSiger(1, "b");
    const sig2 = makeSiger(2, "c");

    await repo.storeControllerSignatures(prefix, digest, [sig0]);
    await repo.storeControllerSignatures(prefix, digest, [sig1, sig2]);
    // Store sig0 again (should be deduplicated by qb64)
    await repo.storeControllerSignatures(prefix, digest, [sig0]);

    const result = await repo.retrieveControllerSignatures(prefix, digest);
    expect(result).toHaveLength(3);
    expect(result.map((s) => s.qb64)).toEqual(
      expect.arrayContaining([sig0.qb64, sig1.qb64, sig2.qb64]),
    );
  });

  // ---------------------------------------------------------------------------
  // RP09: storeWitnessSignatures accumulation
  // ---------------------------------------------------------------------------

  it("RP09: storeWitnessSignatures accumulation", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";

    const wsig0 = makeSiger(0, "w0");
    const wsig1 = makeSiger(1, "w1");

    await repo.storeWitnessSignatures(prefix, digest, [wsig0]);
    await repo.storeWitnessSignatures(prefix, digest, [wsig1]);
    // Duplicate should be ignored
    await repo.storeWitnessSignatures(prefix, digest, [wsig0]);

    const result = await repo.retrieveWitnessSignatures(prefix, digest);
    expect(result).toHaveLength(2);
    expect(result.map((s) => s.qb64)).toContain(wsig0.qb64);
    expect(result.map((s) => s.qb64)).toContain(wsig1.qb64);
  });

  // ---------------------------------------------------------------------------
  // RP10: Non-transferable receipt storage
  // ---------------------------------------------------------------------------

  it("RP10: non-transferable receipt storage", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";

    const receipt1 = {
      receiptorPrefix: "BWit100000000000000000000000000000000000000",
      sigRaw: new Uint8Array([1, 2, 3]),
      sigQb64: "cigar_1",
    };
    const receipt2 = {
      receiptorPrefix: "BWit200000000000000000000000000000000000000",
      sigRaw: new Uint8Array([4, 5, 6]),
      sigQb64: "cigar_2",
    };

    await repo.storeNonTransferableReceipts(prefix, digest, [receipt1]);
    await repo.storeNonTransferableReceipts(prefix, digest, [receipt2]);
    // Duplicate should be ignored
    await repo.storeNonTransferableReceipts(prefix, digest, [receipt1]);

    const result = await repo.retrieveNonTransferableReceipts(prefix, digest);
    expect(result).toHaveLength(2);
    expect(result[0].receiptorPrefix).toBe(receipt1.receiptorPrefix);
    expect(result[1].receiptorPrefix).toBe(receipt2.receiptorPrefix);
  });

  // ---------------------------------------------------------------------------
  // RP11: Transferable receipt storage
  // ---------------------------------------------------------------------------

  it("RP11: transferable receipt storage", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";

    const sig1 = makeSiger(0, "t1");
    const sig2 = makeSiger(1, "t2");

    const receipt1 = {
      receiptorPrefix: "EReceipt1000000000000000000000000000000000",
      receiptorSn: 0,
      receiptorSaid: "ESaid1000000000000000000000000000000000000000",
      siger: sig1,
    };
    const receipt2 = {
      receiptorPrefix: "EReceipt2000000000000000000000000000000000",
      receiptorSn: 1,
      receiptorSaid: "ESaid2000000000000000000000000000000000000000",
      siger: sig2,
    };

    await repo.storeTransferableReceipts(prefix, digest, [receipt1]);
    await repo.storeTransferableReceipts(prefix, digest, [receipt2]);
    // Duplicate should be ignored
    await repo.storeTransferableReceipts(prefix, digest, [receipt1]);

    const result = await repo.retrieveTransferableReceipts(prefix, digest);
    expect(result).toHaveLength(2);
    expect(result[0].receiptorPrefix).toBe(receipt1.receiptorPrefix);
    expect(result[1].receiptorPrefix).toBe(receipt2.receiptorPrefix);
  });

  // ---------------------------------------------------------------------------
  // RP12: datetime storage
  // ---------------------------------------------------------------------------

  it("RP12: datetime storage", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";
    const datetime = "2026-03-10T12:00:00.000Z";

    await repo.storeDatetime(prefix, digest, datetime);
    const result = await repo.retrieveDatetime(prefix, digest);
    expect(result).toBe(datetime);

    // storeDatetime is write-once (first call wins)
    await repo.storeDatetime(prefix, digest, "2099-01-01T00:00:00.000Z");
    const result2 = await repo.retrieveDatetime(prefix, digest);
    expect(result2).toBe(datetime); // original preserved

    // Non-existent returns undefined
    const missing = await repo.retrieveDatetime("ENone", "ENone");
    expect(missing).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // RP13: provenance storage
  // ---------------------------------------------------------------------------

  it("RP13: provenance storage", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";
    const provenance: EventProvenance = { local: true };

    await repo.storeProvenance(prefix, digest, provenance);
    const result = await repo.retrieveProvenance(prefix, digest);
    expect(result).toEqual(provenance);

    // Non-existent
    const missing = await repo.retrieveProvenance("ENone", "ENone");
    expect(missing).toBeUndefined();

    // Different provenance for different event
    await repo.storeProvenance(prefix, "EDigest2", { local: false });
    const result2 = await repo.retrieveProvenance(prefix, "EDigest2");
    expect(result2).toEqual({ local: false });
  });

  // ---------------------------------------------------------------------------
  // RP14: delegation seal store/retrieve/remove
  // ---------------------------------------------------------------------------

  it("RP14: delegation seal store/retrieve/remove", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";

    await repo.storeDelegationSeal(prefix, digest, 5, "EDelegatorDigest0000000000000000000000000000");
    const result = await repo.retrieveDelegationSeal(prefix, digest);
    expect(result).toBeDefined();
    expect(result!.seqNum).toBe(5);
    expect(result!.digest).toBe("EDelegatorDigest0000000000000000000000000000");

    // Remove
    await repo.removeDelegationSeal(prefix, digest);
    const gone = await repo.retrieveDelegationSeal(prefix, digest);
    expect(gone).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // RP15: witness state storage
  // ---------------------------------------------------------------------------

  it("RP15: witness state storage", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const digest = "EDigest0000000000000000000000000000000000000";
    const witnesses = [
      "BWit1000000000000000000000000000000000000000",
      "BWit2000000000000000000000000000000000000000",
    ];

    await repo.storeWitnessState(prefix, digest, witnesses);
    const result = await repo.retrieveWitnessState(prefix, digest);
    expect(result).toEqual(witnesses);

    // Non-existent
    const missing = await repo.retrieveWitnessState("ENone", "ENone");
    expect(missing).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // RP16: KeyStateSnapshot roundtrip
  // ---------------------------------------------------------------------------

  it("RP16: KeyStateSnapshot roundtrip", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const snap = fakeSnapshot({ i: prefix });

    await repo.storeKeyStateSnapshot(prefix, snap);
    const result = await repo.retrieveKeyStateSnapshot(prefix);
    expect(result).toEqual(snap);

    // Non-existent
    const missing = await repo.retrieveKeyStateSnapshot("ENone");
    expect(missing).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // RP17: For each EscrowType: add -> iterate -> present -> remove -> gone
  // ---------------------------------------------------------------------------

  it("RP17: escrow lifecycle for each EscrowType", async () => {
    const repo = makeRepo();

    for (const escrowType of Object.values(EscrowType)) {
      const prefix = `E_${escrowType}_prefix`;
      const sn = 1;
      const digest = `E_${escrowType}_digest`;

      // Add to escrow
      await repo.addToEscrow(escrowType, prefix, sn, digest);

      // Iterate: should be present
      const entries: Array<{ prefix: string; sn: number; digest: string }> = [];
      for await (const entry of repo.iterateEscrow(escrowType)) {
        entries.push(entry);
      }
      expect(entries.length).toBeGreaterThanOrEqual(1);
      const found = entries.find(
        (e) => e.prefix === prefix && e.sn === sn && e.digest === digest,
      );
      expect(found).toBeDefined();

      // Remove
      await repo.removeFromEscrow(escrowType, prefix, sn, digest);

      // Iterate: should be gone
      const afterRemove: Array<{ prefix: string; sn: number; digest: string }> = [];
      for await (const entry of repo.iterateEscrow(escrowType)) {
        afterRemove.push(entry);
      }
      const stillFound = afterRemove.find(
        (e) => e.prefix === prefix && e.sn === sn && e.digest === digest,
      );
      expect(stillFound).toBeUndefined();
    }
  });

  // ---------------------------------------------------------------------------
  // RP18: Idempotent escrow add
  // ---------------------------------------------------------------------------

  it("RP18: idempotent escrow add", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const sn = 2;
    const digest = "EDigest0000000000000000000000000000000000000";

    // Add the same entry twice
    await repo.addToEscrow(EscrowType.OOE, prefix, sn, digest);
    await repo.addToEscrow(EscrowType.OOE, prefix, sn, digest);

    const entries: Array<{ prefix: string; sn: number; digest: string }> = [];
    for await (const entry of repo.iterateEscrow(EscrowType.OOE)) {
      entries.push(entry);
    }

    // Should only have one entry (idempotent)
    const matching = entries.filter(
      (e) => e.prefix === prefix && e.sn === sn && e.digest === digest,
    );
    expect(matching).toHaveLength(1);
  });

  // ---------------------------------------------------------------------------
  // RP19: findSealingEvent
  // ---------------------------------------------------------------------------

  it("RP19: findSealingEvent", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";
    const sealDigest = "ESealDigest00000000000000000000000000000000";
    const eventBytes = new TextEncoder().encode('{"t":"ixn","a":[{"d":"seal"}]}');

    // Store the event, then try to find it by seal digest
    await repo.storeEvent(prefix, sealDigest, eventBytes);
    const result = await repo.findSealingEvent(prefix, sealDigest);
    expect(result).toEqual(eventBytes);

    // Non-existent
    const missing = await repo.findSealingEvent("ENone", "ENone");
    expect(missing).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // RP20: Concurrent access (multiple writes/reads -> no corruption)
  // ---------------------------------------------------------------------------

  it("RP20: concurrent access - multiple writes/reads -> no corruption", async () => {
    const repo = makeRepo();
    const prefix = "EPrefix0000000000000000000000000000000000000";

    // Run many concurrent operations
    const promises: Promise<void>[] = [];

    for (let i = 0; i < 20; i++) {
      const digest = `EDigest_${i}`;
      const eventBytes = new TextEncoder().encode(`{"sn":${i}}`);

      promises.push(
        (async () => {
          await repo.storeEvent(prefix, digest, eventBytes);
          await repo.appendToEventLog(prefix, i, digest);
          await repo.storeControllerSignatures(prefix, digest, [makeSiger(0, `s${i}`)]);
        })(),
      );
    }

    await Promise.all(promises);

    // All 20 events should be retrievable
    for (let i = 0; i < 20; i++) {
      const digest = `EDigest_${i}`;
      const retrieved = await repo.retrieveEvent(prefix, digest);
      expect(retrieved).toBeDefined();

      const lastDigest = await repo.getLastEventDigest(prefix, i);
      expect(lastDigest).toBe(digest);

      const sigs = await repo.retrieveControllerSignatures(prefix, digest);
      expect(sigs.length).toBeGreaterThanOrEqual(1);
    }
  });
});
