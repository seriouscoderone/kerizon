import type { AID } from "../types/AID.js";
import type { TopicAddress } from "../types/TopicAddress.js";
import type { StoreResult, EgressEvent } from "../types/results.js";
import type { IMailboxStore } from "../interfaces/IMailboxStore.js";
import { topicKey } from "../types/TopicAddress.js";

interface TopicEntry {
  digest: string;
  storedAt: number;
}

/**
 * In-memory reference implementation of IMailboxStore.
 *
 * Uses a two-level content-addressed structure per the spec:
 *   - Topic Index: (TopicAddress, ordinal) → digest
 *   - Message Store: digest → payload bytes
 *
 * Not thread-safe. Not persistent.
 * Intended for testing and prototyping — not for production use.
 *
 * Note: Uses SHA-256 for content hashing. The spec recommends Blake3-256;
 * production implementations should use Blake3-256 via their own IMailboxStore.
 */
export class MemoryMailboxStore implements IMailboxStore {
  /** Topic Index: topicKey → Map<ordinal, TopicEntry> */
  private readonly topics = new Map<string, Map<bigint, TopicEntry>>();
  /** Message Store: digest → payload (content-addressed) */
  private readonly blobs = new Map<string, Uint8Array>();
  private readonly counters = new Map<string, bigint>();
  private readonly provisioned = new Set<string>();

  async store(topic: TopicAddress, payload: Uint8Array): Promise<StoreResult> {
    const key = topicKey(topic);
    if (!this.topics.has(key)) {
      this.topics.set(key, new Map());
      this.counters.set(key, 0n);
    }

    const digest = await sha256Hex(payload);
    const isNew = !this.blobs.has(digest);
    if (isNew) {
      this.blobs.set(digest, payload);
    }

    const ordinal = this.counters.get(key)!;
    this.counters.set(key, ordinal + 1n);
    this.topics.get(key)!.set(ordinal, { digest, storedAt: Date.now() });

    return { ordinal, digest, isNew };
  }

  async *retrieve(
    topic: TopicAddress,
    fromOrdinal: bigint,
  ): AsyncIterable<[bigint, Uint8Array]> {
    const key = topicKey(topic);
    const entries = this.topics.get(key);
    if (!entries) return;
    const ordinals = [...entries.keys()].sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    for (const ordinal of ordinals) {
      if (ordinal >= fromOrdinal) {
        const entry = entries.get(ordinal)!;
        const payload = this.blobs.get(entry.digest);
        if (payload) yield [ordinal, payload];
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
    const entries = this.topics.get(key);
    if (!entries) return 0n;
    let deleted = 0n;
    for (const ordinal of [...entries.keys()]) {
      if (ordinal < beforeOrdinal) {
        entries.delete(ordinal);
        deleted++;
      }
    }
    return deleted;
  }

  async trimByAge(recipient: AID, maxAge: number): Promise<bigint> {
    const cutoff = Date.now() - maxAge;
    let deleted = 0n;
    const prefix = `${recipient}/`;
    for (const [key, entries] of this.topics) {
      if (!key.startsWith(prefix)) continue;
      for (const [ordinal, entry] of [...entries.entries()]) {
        if (entry.storedAt <= cutoff) {
          entries.delete(ordinal);
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
