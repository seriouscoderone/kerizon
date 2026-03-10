import type { EscrowReason } from "./EscrowReason.js";

/** Metadata for an escrowed event. */
export interface PendingEvent {
  /** The escrowed event bytes. */
  event: Uint8Array;
  /** AID prefix. */
  prefix: string;
  /** Sequence number. */
  sn: number;
  /** Event SAID. */
  said: string;
  /** Why this event is escrowed. */
  reason: EscrowReason;
  /** Timestamp when escrowed (ms since epoch). */
  escrowedAt: number;
  /** Count of valid controller sigs collected so far. */
  signaturesCollected: number;
  /** Total required by signing threshold. */
  signaturesNeeded: number;
  /** Count of valid witness sigs collected so far. */
  witnessesCollected: number;
  /** Total required by TOAD. */
  witnessesNeeded: number;
  /** Whether the escrow timeout has elapsed. */
  isExpired: boolean;
}
