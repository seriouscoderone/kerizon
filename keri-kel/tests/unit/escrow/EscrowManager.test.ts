import { describe, it, expect } from "vitest";
import { EscrowManager } from "../../../src/core/escrow/EscrowManager.js";
import { MemoryEscrowStore } from "../../../src/memory/MemoryEscrowStore.js";
import { MemoryEventDatabase } from "../../../src/memory/MemoryEventDatabase.js";
import { EscrowReason } from "../../../src/types/EscrowReason.js";

describe("EscrowManager", () => {
  function makeManager() {
    const store = new MemoryEscrowStore();
    const db = new MemoryEventDatabase();
    return new EscrowManager(store, db);
  }

  it("escrows and retrieves pending events", async () => {
    const mgr = makeManager();
    await mgr.escrow(EscrowReason.PARTIAL_SIGNATURES, "EABC", 1, "ESAID1", {
      sigsCollected: 1,
      sigsNeeded: 2,
    });

    const pending = await mgr.pendingFor("EABC");
    expect(pending).toHaveLength(1);
    expect(pending[0].reason).toBe(EscrowReason.PARTIAL_SIGNATURES);
    expect(pending[0].signaturesCollected).toBe(1);
    expect(pending[0].signaturesNeeded).toBe(2);
  });

  it("retrieves pending by reason", async () => {
    const mgr = makeManager();
    await mgr.escrow(EscrowReason.OUT_OF_ORDER, "EABC", 5, "ESAID5");
    await mgr.escrow(EscrowReason.PARTIAL_SIGNATURES, "EABC", 1, "ESAID1");

    const ooe = await mgr.pendingByReason(EscrowReason.OUT_OF_ORDER);
    expect(ooe).toHaveLength(1);
    expect(ooe[0].sn).toBe(5);
  });

  it("checks isPending", async () => {
    const mgr = makeManager();
    await mgr.escrow(EscrowReason.OUT_OF_ORDER, "EABC", 5, "ESAID5");

    expect(await mgr.isPending("EABC", 5)).toBe(true);
    expect(await mgr.isPending("EABC", 3)).toBe(false);
    expect(await mgr.isPending("EOTHER", 5)).toBe(false);
  });

  it("resolves an escrowed event", async () => {
    const mgr = makeManager();
    await mgr.escrow(EscrowReason.OUT_OF_ORDER, "EABC", 5, "ESAID5");
    await mgr.resolve(EscrowReason.OUT_OF_ORDER, "EABC", 5, "ESAID5");

    expect(await mgr.isPending("EABC", 5)).toBe(false);
  });

  it("processes escrows in order, resolving when callback returns true", async () => {
    const mgr = makeManager();
    await mgr.escrow(EscrowReason.PARTIAL_SIGNATURES, "EABC", 1, "ESAID1");
    await mgr.escrow(EscrowReason.OUT_OF_ORDER, "EABC", 5, "ESAID5");

    const processedOrder: string[] = [];
    const resolved = await mgr.processEscrows(async (reason, entry) => {
      processedOrder.push(`${reason}:${entry.sn}`);
      return true; // resolve all
    });

    // OOE should be processed first
    expect(processedOrder[0]).toBe("out_of_order:5");
    expect(processedOrder[1]).toBe("partial_signatures:1");
    expect(resolved).toHaveLength(2);

    // All should be resolved now
    expect(await mgr.pendingFor("EABC")).toHaveLength(0);
  });

  it("removes expired escrows", async () => {
    const mgr = makeManager();
    // Escrow with a timestamp in the distant past
    await mgr.escrow(EscrowReason.OUT_OF_ORDER, "EABC", 5, "ESAID5", {
      escrowedAt: Date.now() - 99_999_999, // way past timeout
    });

    const resolved = await mgr.processEscrows(async () => false);
    // Should have been removed due to timeout, not resolved
    expect(resolved).toHaveLength(0);
    expect(await mgr.isPending("EABC", 5)).toBe(false);
  });

  it("keeps non-resolved, non-expired escrows", async () => {
    const mgr = makeManager();
    await mgr.escrow(EscrowReason.PARTIAL_SIGNATURES, "EABC", 1, "ESAID1");

    const resolved = await mgr.processEscrows(async () => false);
    expect(resolved).toHaveLength(0);
    // Should still be pending
    expect(await mgr.isPending("EABC", 1)).toBe(true);
  });
});
