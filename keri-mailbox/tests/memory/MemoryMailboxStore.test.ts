import { describe, it, expect, beforeEach } from "vitest";
import { MemoryMailboxStore } from "../../src/memory/MemoryMailboxStore.js";
import { dummyAID } from "../helpers.js";
import type { TopicAddress } from "../../src/types/TopicAddress.js";

const alice = dummyAID("Alice");
const bob = dummyAID("Bob");
const topic: TopicAddress = { recipient: alice, topic: "notice" };

describe("MemoryMailboxStore", () => {
  let store: MemoryMailboxStore;

  beforeEach(() => {
    store = new MemoryMailboxStore();
  });

  describe("provision / isProvisioned / deprovision / listProvisioned", () => {
    it("is not provisioned by default", async () => {
      expect(await store.isProvisioned(alice)).toBe(false);
    });

    it("provisions an AID", async () => {
      await store.provision(alice);
      expect(await store.isProvisioned(alice)).toBe(true);
    });

    it("deprovisions an AID", async () => {
      await store.provision(alice);
      await store.deprovision(alice);
      expect(await store.isProvisioned(alice)).toBe(false);
    });

    it("lists provisioned AIDs", async () => {
      await store.provision(alice);
      await store.provision(bob);
      const list = await store.listProvisioned();
      expect(list).toContain(alice);
      expect(list).toContain(bob);
      expect(list).toHaveLength(2);
    });
  });

  describe("store / retrieve", () => {
    it("assigns ordinals starting from 0", async () => {
      const r1 = await store.store(topic, new Uint8Array([1]));
      const r2 = await store.store(topic, new Uint8Array([2]));
      expect(r1.ordinal).toBe(0n);
      expect(r2.ordinal).toBe(1n);
    });

    it("returns a hex digest", async () => {
      const result = await store.store(topic, new Uint8Array([1, 2, 3]));
      expect(result.digest).toMatch(/^[0-9a-f]{64}$/);
    });

    it("retrieves messages from ordinal 0", async () => {
      const p1 = new Uint8Array([1]);
      const p2 = new Uint8Array([2]);
      await store.store(topic, p1);
      await store.store(topic, p2);

      const results: Array<[bigint, Uint8Array]> = [];
      for await (const entry of store.retrieve(topic, 0n)) {
        results.push(entry);
      }
      expect(results).toHaveLength(2);
      expect(results[0]).toEqual([0n, p1]);
      expect(results[1]).toEqual([1n, p2]);
    });

    it("retrieves from a specific ordinal", async () => {
      for (let i = 0; i < 5; i++) {
        await store.store(topic, new Uint8Array([i]));
      }
      const results: Array<[bigint, Uint8Array]> = [];
      for await (const entry of store.retrieve(topic, 3n)) {
        results.push(entry);
      }
      expect(results).toHaveLength(2);
      expect(results[0][0]).toBe(3n);
      expect(results[1][0]).toBe(4n);
    });

    it("returns nothing for unknown topic", async () => {
      const results: Array<[bigint, Uint8Array]> = [];
      for await (const entry of store.retrieve(
        { recipient: alice, topic: "unknown" },
        0n,
      )) {
        results.push(entry);
      }
      expect(results).toHaveLength(0);
    });
  });

  describe("retrieveMulti", () => {
    it("yields events across multiple topics", async () => {
      const t1: TopicAddress = { recipient: alice, topic: "a" };
      const t2: TopicAddress = { recipient: alice, topic: "b" };
      await store.store(t1, new Uint8Array([1]));
      await store.store(t2, new Uint8Array([2]));

      const events = [];
      for await (const ev of store.retrieveMulti(
        alice,
        new Map([
          ["a", 0n],
          ["b", 0n],
        ]),
      )) {
        events.push(ev);
      }
      expect(events).toHaveLength(2);
    });
  });

  describe("trim", () => {
    it("deletes messages before the given ordinal", async () => {
      for (let i = 0; i < 5; i++) {
        await store.store(topic, new Uint8Array([i]));
      }
      const deleted = await store.trim(topic, 3n);
      expect(deleted).toBe(3n);

      const remaining: bigint[] = [];
      for await (const [ord] of store.retrieve(topic, 0n)) {
        remaining.push(ord);
      }
      expect(remaining).toEqual([3n, 4n]);
    });
  });

  describe("trimByAge", () => {
    it("deletes messages older than maxAge", async () => {
      await store.store(topic, new Uint8Array([1]));
      // Wait a tiny bit and use 0ms maxAge to force deletion
      const deleted = await store.trimByAge(alice, 0);
      expect(deleted).toBeGreaterThanOrEqual(1n);
    });

    it("does not delete recent messages", async () => {
      await store.store(topic, new Uint8Array([1]));
      const deleted = await store.trimByAge(alice, 60_000);
      expect(deleted).toBe(0n);
    });
  });
});
