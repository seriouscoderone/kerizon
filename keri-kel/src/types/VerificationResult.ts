import type { EscrowReason } from "./EscrowReason.js";

/** The event was accepted and key state updated. */
export interface Accepted {
  type: "accepted";
  /** Updated key state prefix. */
  prefix: string;
  /** Sequence number of the accepted event. */
  sn: number;
  /** SAID of the accepted event. */
  said: string;
  /** Assigned first-seen ordinal. */
  fn: number;
}

/** The event was escrowed due to a missing dependency. */
export interface Escrowed {
  type: "escrowed";
  /** Why the event was escrowed. */
  reason: EscrowReason;
  /** Human-readable detail. */
  message: string;
}

/** The event was rejected due to structural or cryptographic invalidity. */
export interface Rejected {
  type: "rejected";
  /** Error details. */
  errors: string[];
}

/** Three-way result from the verification pipeline. */
export type VerificationResult = Accepted | Escrowed | Rejected;
