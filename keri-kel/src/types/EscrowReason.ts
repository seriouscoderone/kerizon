/** Typed escrow reasons replacing cryptic database table names. */
export enum EscrowReason {
  /** Signatures below signing threshold. */
  PARTIAL_SIGNATURES = "partial_signatures",
  /** Witness signatures below TOAD. */
  PARTIAL_WITNESSES = "partial_witnesses",
  /** Prior event not yet in KEL. */
  OUT_OF_ORDER = "out_of_order",
  /** Different SAID at same sn. */
  LIKELY_DUPLICITOUS = "likely_duplicitous",
  /** Delegator seal not found. */
  PENDING_DELEGATION = "pending_delegation",
  /** Local delegation awaiting approval. */
  DELEGABLE = "delegable",
  /** Remote source for local-owned event. */
  MISFIT_SOURCE = "misfit_source",
}

/** Default timeout values (in milliseconds) per escrow type. */
export const ESCROW_TIMEOUTS: Record<EscrowReason, number> = {
  [EscrowReason.PARTIAL_SIGNATURES]: 3600_000,
  [EscrowReason.PARTIAL_WITNESSES]: 3600_000,
  [EscrowReason.OUT_OF_ORDER]: 1200_000,
  [EscrowReason.LIKELY_DUPLICITOUS]: 3600_000,
  [EscrowReason.PENDING_DELEGATION]: 3600_000,
  [EscrowReason.DELEGABLE]: 3600_000,
  [EscrowReason.MISFIT_SOURCE]: 3600_000,
};
