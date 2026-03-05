import type { EscrowReason } from "../types/EscrowReason.js";

/** An entry in an escrow store. */
export interface EscrowEntry {
  prefix: string;
  sn: number;
  said: string;
}

/** Delegation seal info stored alongside escrowed events. */
export interface SealInfo {
  /** Delegator prefix. */
  delegatorPrefix: string;
  /** Sequence number of the anchoring event in the delegator's KEL. */
  delegatorSn: number;
  /** SAID of the anchoring event. */
  delegatorSaid: string;
}

/**
 * Storage contract for escrowed events.
 * Consumers provide their own implementation.
 */
export interface IEscrowStore {
  /** Add event to escrow. Supports duplicates at same (prefix, sn). */
  add(
    escrowType: EscrowReason,
    prefix: string,
    sn: number,
    said: string,
  ): Promise<void>;

  /** Remove specific event from escrow. */
  remove(
    escrowType: EscrowReason,
    prefix: string,
    sn: number,
    said: string,
  ): Promise<void>;

  /** Iterate all entries in escrow type (for periodic processing). */
  iterate(escrowType: EscrowReason): AsyncIterable<EscrowEntry>;

  /** Get all entries for a specific prefix and escrow type. */
  getByPrefix(
    escrowType: EscrowReason,
    prefix: string,
  ): Promise<EscrowEntry[]>;

  /** Check if an entry exists in a specific escrow. */
  has(
    escrowType: EscrowReason,
    prefix: string,
    sn: number,
    said: string,
  ): Promise<boolean>;

  /** Store delegation seal info. Non-idempotent (pin/replace). */
  putSource(prefix: string, said: string, sealInfo: SealInfo): Promise<void>;

  /** Get delegation seal info. */
  getSource(prefix: string, said: string): Promise<SealInfo | undefined>;
}
