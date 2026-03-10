import type { IndexedSiger } from "../verification.js";
import type { KeyStateSnapshot, EventProvenance } from "../types.js";

export enum EscrowType {
  OOE = "ooe",
  PSE = "pse",
  PWE = "pwe",
  PDE = "pde",
  DELEGABLE = "delegable",
  MFE = "mfe",
  UWE = "uwe",
  URE = "ure",
  VRE = "vre",
  LDE = "lde",
}

/** A non-transferable receipt (witness prefix + cigar). */
export interface NonTransferableReceipt {
  receiptorPrefix: string;
  sigRaw: Uint8Array;
  sigQb64: string;
}

/** A transferable receipt (receiptor AID, sn, digest, indexed sig). */
export interface TransferableReceipt {
  receiptorPrefix: string;
  receiptorSn: number;
  receiptorSaid: string;
  siger: IndexedSiger;
}

/**
 * Unified repository interface for KEL event storage.
 * Combines event storage, escrow management, and receipt storage
 * into a single interface.
 */
export interface EventRepository {
  // ── Event storage ─────────────────────────────────────────────────

  storeEvent(
    prefix: string,
    digest: string,
    event: Uint8Array,
  ): Promise<void>;

  retrieveEvent(
    prefix: string,
    digest: string,
  ): Promise<Uint8Array | undefined>;

  // ── Log indexes ───────────────────────────────────────────────────

  appendToEventLog(
    prefix: string,
    sequenceNumber: number,
    digest: string,
  ): Promise<void>;

  getLastEventDigest(
    prefix: string,
    sequenceNumber: number,
  ): Promise<string | undefined>;

  iterateEventLogBackward(
    prefix: string,
  ): AsyncIterable<{ sn: number; digest: string }>;

  appendToFirstSeenLog(prefix: string, digest: string): Promise<number>;

  storeFirstSeenOrdinal(
    prefix: string,
    digest: string,
    ordinal: number,
  ): Promise<void>;

  getFirstSeenOrdinal(
    prefix: string,
    digest: string,
  ): Promise<number | undefined>;

  // ── Signatures ────────────────────────────────────────────────────

  storeControllerSignatures(
    prefix: string,
    digest: string,
    signatures: IndexedSiger[],
  ): Promise<void>;

  retrieveControllerSignatures(
    prefix: string,
    digest: string,
  ): Promise<IndexedSiger[]>;

  storeWitnessSignatures(
    prefix: string,
    digest: string,
    signatures: IndexedSiger[],
  ): Promise<void>;

  retrieveWitnessSignatures(
    prefix: string,
    digest: string,
  ): Promise<IndexedSiger[]>;

  storeNonTransferableReceipts(
    prefix: string,
    digest: string,
    couples: NonTransferableReceipt[],
  ): Promise<void>;

  retrieveNonTransferableReceipts(
    prefix: string,
    digest: string,
  ): Promise<NonTransferableReceipt[]>;

  storeTransferableReceipts(
    prefix: string,
    digest: string,
    quadruples: TransferableReceipt[],
  ): Promise<void>;

  retrieveTransferableReceipts(
    prefix: string,
    digest: string,
  ): Promise<TransferableReceipt[]>;

  // ── Metadata ──────────────────────────────────────────────────────

  storeDatetime(
    prefix: string,
    digest: string,
    datetime: string,
  ): Promise<void>;

  retrieveDatetime(
    prefix: string,
    digest: string,
  ): Promise<string | undefined>;

  storeProvenance(
    prefix: string,
    digest: string,
    provenance: EventProvenance,
  ): Promise<void>;

  retrieveProvenance(
    prefix: string,
    digest: string,
  ): Promise<EventProvenance | undefined>;

  storeDelegationSeal(
    prefix: string,
    digest: string,
    seqNum: number,
    delegatorDigest: string,
  ): Promise<void>;

  retrieveDelegationSeal(
    prefix: string,
    digest: string,
  ): Promise<{ seqNum: number; digest: string } | undefined>;

  removeDelegationSeal(prefix: string, digest: string): Promise<void>;

  storeWitnessState(
    prefix: string,
    digest: string,
    witnesses: string[],
  ): Promise<void>;

  retrieveWitnessState(
    prefix: string,
    digest: string,
  ): Promise<string[] | undefined>;

  storeKeyStateSnapshot(
    prefix: string,
    snapshot: KeyStateSnapshot,
  ): Promise<void>;

  retrieveKeyStateSnapshot(
    prefix: string,
  ): Promise<KeyStateSnapshot | undefined>;

  // ── Parameterized escrow ops ──────────────────────────────────────

  addToEscrow(
    escrowType: EscrowType,
    prefix: string,
    sequenceNumber: number,
    digest: string,
  ): Promise<void>;

  iterateEscrow(
    escrowType: EscrowType,
  ): AsyncIterable<{ prefix: string; sn: number; digest: string }>;

  removeFromEscrow(
    escrowType: EscrowType,
    prefix: string,
    sequenceNumber: number,
    digest: string,
  ): Promise<void>;

  // ── Query ─────────────────────────────────────────────────────────

  findSealingEvent(
    prefix: string,
    sealDigest: string,
  ): Promise<Uint8Array | undefined>;
}
