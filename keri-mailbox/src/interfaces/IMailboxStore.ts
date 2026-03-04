import type { AID } from "../types/AID.js";
import type { TopicAddress } from "../types/TopicAddress.js";
import type { StoreResult, EgressEvent } from "../types/results.js";

/**
 * Storage contract for the mailbox.
 * Consumers provide their own implementation (Postgres, LMDB, SQLite, etc.).
 */
export interface IMailboxStore {
  /**
   * Append a payload to a topic, returning its assigned ordinal and SHA-256 digest.
   * Ordinals are monotonically increasing per TopicAddress starting from 0.
   */
  store(topic: TopicAddress, payload: Uint8Array): Promise<StoreResult>;

  /**
   * Yield [ordinal, payload] pairs for a topic, in ascending ordinal order,
   * starting at fromOrdinal (inclusive).
   */
  retrieve(topic: TopicAddress, fromOrdinal: bigint): AsyncIterable<[bigint, Uint8Array]>;

  /**
   * Yield EgressEvent objects for a recipient across multiple topics.
   * topicCursors maps topic name → exclusive lower bound ordinal.
   */
  retrieveMulti(
    recipient: AID,
    topicCursors: Map<string, bigint>,
  ): AsyncIterable<EgressEvent>;

  /** Mark an AID as a provisioned mailbox recipient. */
  provision(recipient: AID): Promise<void>;

  /** Remove an AID from the provisioned set. */
  deprovision(recipient: AID): Promise<void>;

  /** Return true if the AID is currently provisioned. */
  isProvisioned(recipient: AID): Promise<boolean>;

  /** Return all provisioned recipient AIDs. */
  listProvisioned(): Promise<AID[]>;

  /**
   * Delete messages with ordinal < beforeOrdinal for a topic.
   * Returns the count of deleted messages.
   */
  trim(topic: TopicAddress, beforeOrdinal: bigint): Promise<bigint>;

  /**
   * Delete messages older than maxAge milliseconds for all topics of a recipient.
   * Returns the count of deleted messages.
   */
  trimByAge(recipient: AID, maxAge: number): Promise<bigint>;
}
