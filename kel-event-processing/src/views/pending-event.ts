export enum EscrowReason {
  PARTIAL_SIGNATURES = "partial_signatures",
  PARTIAL_WITNESSES = "partial_witnesses",
  OUT_OF_ORDER = "out_of_order",
  LIKELY_DUPLICITOUS = "likely_duplicitous",
  PENDING_DELEGATION = "pending_delegation",
  DELEGABLE = "delegable",
  MISFIT_SOURCE = "misfit_source",
  UNVERIFIED_WITNESS_RECEIPT = "unverified_witness_receipt",
  UNVERIFIED_RECEIPT = "unverified_receipt",
  UNVERIFIED_TRANSFERABLE_RECEIPT = "unverified_transferable_receipt",
}

export interface PendingEvent {
  event: Uint8Array;
  prefix: string;
  sn: number;
  said: string;
  reason: EscrowReason;
  escrowedAt: number;
  signaturesCollected: number;
  signaturesNeeded: number;
  witnessesCollected: number;
  witnessesNeeded: number;
  isExpired: boolean;
}
