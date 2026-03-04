import type { AID } from "../types/AID.js";
import type { TopicAddress } from "../types/TopicAddress.js";
import type { StoreResult, EgressEvent } from "../types/results.js";
import type { IMailboxStore } from "../interfaces/IMailboxStore.js";
import { topicKey } from "../types/TopicAddress.js";

interface StoredMessage {
  payload: Uint8Array;
  storedAt: number;
}

/**
 * In-memory reference implementation of IMailboxStore.
 *
 * Uses plain Map/Set structures. Not thread-safe. Not persistent.
 * Intended for testing and prototyping — not for production use.
 */
export class MemoryMailboxStore implements IMailboxStore {
  private readonly messages = new Map<string, Map<bigint, StoredMessage>>();
  private readonly counters = new Map<string, bigint>();
  private readonly provisioned = new Set<string>();

  async store(topic: TopicAddress, payload: Uint8Array): Promise<StoreResult> {
    const key = topicKey(topic);
    if (!this.messages.has(key)) {
      this.messages.set(key, new Map());
      this.counters.set(key, 0n);
    }
    const ordinal = this.counters.get(key)!;
    this.counters.set(key, ordinal + 1n);
    this.messages.get(key)!.set(ordinal, { payload, storedAt: Date.now() });
    const digest = await sha256Hex(payload);
    return { ordinal, digest };
  }

  async *retrieve(
    topic: TopicAddress,
    fromOrdinal: bigint,
  ): AsyncIterable<[bigint, Uint8Array]> {
    const key = topicKey(topic);
    const topicMessages = this.messages.get(key);
    if (!topicMessages) return;
    const ordinals = [...topicMessages.keys()].sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    for (const ordinal of ordinals) {
      if (ordinal >= fromOrdinal) {
        yield [ordinal, topicMessages.get(ordinal)!.payload];
      }
    }
  }

  async *retrieveMulti(
    recipient: AID,
    topicCursors: Map<string, bigint>,
  ): AsyncIterable<EgressEvent> {
    for (const [topic, fromOrdinal] of topicCursors) {
      const topicAddr: TopicAddress = { recipient, topic };
      for await (const [ordinal, payload] of this.retrieve(
        topicAddr,
        fromOrdinal,
      )) {
        yield { topic: topicAddr, ordinal, payload };
      }
    }
  }

  async provision(recipient: AID): Promise<void> {
    this.provisioned.add(recipient);
  }

  async deprovision(recipient: AID): Promise<void> {
    this.provisioned.delete(recipient);
  }

  async isProvisioned(recipient: AID): Promise<boolean> {
    return this.provisioned.has(recipient);
  }

  async listProvisioned(): Promise<AID[]> {
    return [...this.provisioned] as AID[];
  }

  async trim(topic: TopicAddress, beforeOrdinal: bigint): Promise<bigint> {
    const key = topicKey(topic);
    const topicMessages = this.messages.get(key);
    if (!topicMessages) return 0n;
    let deleted = 0n;
    for (const ordinal of [...topicMessages.keys()]) {
      if (ordinal < beforeOrdinal) {
        topicMessages.delete(ordinal);
        deleted++;
      }
    }
    return deleted;
  }

  async trimByAge(recipient: AID, maxAge: number): Promise<bigint> {
    const cutoff = Date.now() - maxAge;
    let deleted = 0n;
    const prefix = `${recipient}/`;
    for (const [key, topicMessages] of this.messages) {
      if (!key.startsWith(prefix)) continue;
      for (const [ordinal, msg] of [...topicMessages.entries()]) {
        if (msg.storedAt <= cutoff) {
          topicMessages.delete(ordinal);
          deleted++;
        }
      }
    }
    return deleted;
  }
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", data.slice());
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
