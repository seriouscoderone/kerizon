import { describe, it, expect, beforeEach } from "vitest";
import type { HashFn } from "cesr-ts";
import { EscrowManager } from "../../src/core/escrow/EscrowManager.js";
import { MemoryEscrowStore } from "../../src/memory/MemoryEscrowStore.js";
import { MemoryEventDatabase } from "../../src/memory/MemoryEventDatabase.js";
import { EscrowReason } from "../../src/types/EscrowReason.js";
import { InceptionBuilder } from "../../src/builders/InceptionBuilder.js";
import { InteractionBuilder } from "../../src/builders/InteractionBuilder.js";
import { generateKeyPair } from "../helpers.js";

function testHash(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(32);
  for (let i = 0; i < data.length; i++) {
    result[i % 32] ^= data[i];
  }
  return result;
}

const hashFn: HashFn = testHash;

describe("Escrow lifecycle", () => {
  let escrowStore: MemoryEscrowStore;
  let db: MemoryEventDatabase;
  let escrowMgr: EscrowManager;

  beforeEach(() => {
    escrowStore = new MemoryEscrowStore();
    db = new MemoryEventDatabase();
    escrowMgr = new EscrowManager(escrowStore, db);
  });

  it("escrows OOO event, then resolves when prior arrives", async () => {
    const kp = await generateKeyPair();

    const icpEvent = new InceptionBuilder(hashFn)
      .signingKeys([kp.verferQb64])
      .build();

    const prefix = icpEvent.prefix;

    // Build an ixn at sn=2 (out-of-order)
    const ixnEvent = new InteractionBuilder(hashFn)
      .identifier(prefix)
      .sequenceNumber(2)
      .previousEvent("Efake_prev")
      .build();

    // Escrow the OOO event
    await escrowMgr.escrow(
      EscrowReason.OUT_OF_ORDER,
      prefix,
      2,
      ixnEvent.said,
    );

    // Verify it's pending
    const pending = await escrowMgr.pendingFor(prefix);
    expect(pending).toHaveLength(1);
    expect(pending[0].sn).toBe(2);
    expect(pending[0].reason).toBe(EscrowReason.OUT_OF_ORDER);

    expect(await escrowMgr.isPending(prefix, 2)).toBe(true);
    expect(await escrowMgr.isPending(prefix, 1)).toBe(false);

    // Check by reason
    const oooEvents = await escrowMgr.pendingByReason(EscrowReason.OUT_OF_ORDER);
    expect(oooEvents).toHaveLength(1);

    // Now "resolve" it (prior event arrived)
    await escrowMgr.resolve(EscrowReason.OUT_OF_ORDER, prefix, 2, ixnEvent.said);

    // Should no longer be pending
    const afterResolve = await escrowMgr.pendingFor(prefix);
    expect(afterResolve).toHaveLength(0);
    expect(await escrowMgr.isPending(prefix, 2)).toBe(false);
  });

  it("escrows partial-signature event", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    const icpEvent = new InceptionBuilder(hashFn)
      .signingKeys([kp1.verferQb64, kp2.verferQb64])
      .signingThreshold("2")
      .build();

    await escrowMgr.escrow(
      EscrowReason.PARTIAL_SIGNATURES,
      icpEvent.prefix,
      0,
      icpEvent.said,
    );

    const psePending = await escrowMgr.pendingByReason(EscrowReason.PARTIAL_SIGNATURES);
    expect(psePending).toHaveLength(1);

    // Resolve
    await escrowMgr.resolve(EscrowReason.PARTIAL_SIGNATURES, icpEvent.prefix, 0, icpEvent.said);
    const afterResolve = await escrowMgr.pendingByReason(EscrowReason.PARTIAL_SIGNATURES);
    expect(afterResolve).toHaveLength(0);
  });

  it("manages multiple escrow types for same identifier", async () => {
    const prefix = "Etest_multi_escrow";

    await escrowMgr.escrow(EscrowReason.OUT_OF_ORDER, prefix, 3, "Esaid3");
    await escrowMgr.escrow(EscrowReason.PARTIAL_SIGNATURES, prefix, 4, "Esaid4");

    const allPending = await escrowMgr.pendingFor(prefix);
    expect(allPending).toHaveLength(2);

    // Resolve OOO
    await escrowMgr.resolve(EscrowReason.OUT_OF_ORDER, prefix, 3, "Esaid3");
    const remaining = await escrowMgr.pendingFor(prefix);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].reason).toBe(EscrowReason.PARTIAL_SIGNATURES);
  });

  it("processes escrows with callback", async () => {
    const prefix = "Eprocess_test";

    await escrowMgr.escrow(EscrowReason.OUT_OF_ORDER, prefix, 1, "Esaid1");
    await escrowMgr.escrow(EscrowReason.PARTIAL_SIGNATURES, prefix, 2, "Esaid2");

    const processed: string[] = [];

    await escrowMgr.processEscrows(async (reason, entry) => {
      processed.push(`${reason}:${entry.sn}`);
      return true; // resolved
    });

    expect(processed).toHaveLength(2);
    const remaining = await escrowMgr.pendingFor(prefix);
    expect(remaining).toHaveLength(0);
  });
});
