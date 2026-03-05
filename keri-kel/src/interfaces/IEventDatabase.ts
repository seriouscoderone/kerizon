import type { KeyStateRecord } from "../types/KeyStateRecord.js";

/**
 * Storage contract for KEL events and related data.
 * Consumers provide their own implementation (LMDB, SQLite, etc.).
 */
export interface IEventDatabase {
  // -- Event storage --

  /** Store event keyed by (prefix, SAID). Idempotent. */
  putEvent(prefix: string, said: string, event: Uint8Array): Promise<void>;

  /** Retrieve event by (prefix, SAID). */
  getEvent(prefix: string, said: string): Promise<Uint8Array | undefined>;

  // -- KEL sequence index --

  /** Add event SAID to KEL at sequence number. Supports duplicates at same sn. */
  addKelEntry(prefix: string, sn: number, said: string): Promise<void>;

  /** Get all event SAIDs at sequence number for prefix. */
  getKelEntry(prefix: string, sn: number): Promise<string[]>;

  // -- First-seen event log --

  /** Append to first-seen log. Returns assigned fn. */
  appendFel(prefix: string, said: string): Promise<number>;

  /** Get event SAID by first-seen ordinal. */
  getFelEntry(prefix: string, fn: number): Promise<string | undefined>;

  // -- Signature storage --

  /** Store controller signatures. Idempotent (additive). */
  putSigs(
    prefix: string,
    said: string,
    sigers: Array<{ index: number; raw: Uint8Array; qb64: string }>,
  ): Promise<void>;

  /** Get all controller signatures for event. */
  getSigs(
    prefix: string,
    said: string,
  ): Promise<Array<{ index: number; raw: Uint8Array; qb64: string }>>;

  /** Store witness signatures. Idempotent (additive). */
  putWigs(
    prefix: string,
    said: string,
    wigers: Array<{ index: number; raw: Uint8Array; qb64: string }>,
  ): Promise<void>;

  /** Get all witness signatures for event. */
  getWigs(
    prefix: string,
    said: string,
  ): Promise<Array<{ index: number; raw: Uint8Array; qb64: string }>>;

  // -- Timestamp storage --

  /** Store first-seen datetime. Idempotent (first write wins). */
  putDatetime(prefix: string, said: string, datetime: string): Promise<void>;

  /** Get first-seen datetime. */
  getDatetime(prefix: string, said: string): Promise<string | undefined>;

  // -- Key state cache --

  /** Store/update key state snapshot. */
  putState(prefix: string, state: KeyStateRecord): Promise<void>;

  /** Get key state snapshot. */
  getState(prefix: string): Promise<KeyStateRecord | undefined>;

  // -- First-seen ordinal storage --

  /** Store fn for event. */
  putFn(prefix: string, said: string, fn: number): Promise<void>;

  /** Get fn for event. */
  getFn(prefix: string, said: string): Promise<number | undefined>;
}
