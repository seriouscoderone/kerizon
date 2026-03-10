import { EscrowReason, ESCROW_TIMEOUTS } from "../../types/EscrowReason.js";

/** Definition of an escrow type with its timeout. */
export interface EscrowTypeConfig {
  reason: EscrowReason;
  /** Timeout in milliseconds. */
  timeoutMs: number;
}

/** All escrow types with their default timeout configs. */
export const ESCROW_CONFIGS: EscrowTypeConfig[] = [
  { reason: EscrowReason.OUT_OF_ORDER, timeoutMs: ESCROW_TIMEOUTS[EscrowReason.OUT_OF_ORDER] },
  { reason: EscrowReason.PARTIAL_SIGNATURES, timeoutMs: ESCROW_TIMEOUTS[EscrowReason.PARTIAL_SIGNATURES] },
  { reason: EscrowReason.PARTIAL_WITNESSES, timeoutMs: ESCROW_TIMEOUTS[EscrowReason.PARTIAL_WITNESSES] },
  { reason: EscrowReason.PENDING_DELEGATION, timeoutMs: ESCROW_TIMEOUTS[EscrowReason.PENDING_DELEGATION] },
  { reason: EscrowReason.DELEGABLE, timeoutMs: ESCROW_TIMEOUTS[EscrowReason.DELEGABLE] },
  { reason: EscrowReason.LIKELY_DUPLICITOUS, timeoutMs: ESCROW_TIMEOUTS[EscrowReason.LIKELY_DUPLICITOUS] },
  { reason: EscrowReason.MISFIT_SOURCE, timeoutMs: ESCROW_TIMEOUTS[EscrowReason.MISFIT_SOURCE] },
];

/**
 * Processing order for escrow resolution (spec Section 9.4):
 * 1. OOE — resolved events may unblock other escrows
 * 2. PSE — additional signatures may have arrived
 * 3. PWE — witness receipts may have arrived
 * 4. PDE — delegator events may have arrived
 * 5. Delegable — local approval may have been given
 * 6. LDE — check if external resolution occurred
 */
export const ESCROW_PROCESSING_ORDER: EscrowReason[] = [
  EscrowReason.OUT_OF_ORDER,
  EscrowReason.PARTIAL_SIGNATURES,
  EscrowReason.PARTIAL_WITNESSES,
  EscrowReason.PENDING_DELEGATION,
  EscrowReason.DELEGABLE,
  EscrowReason.LIKELY_DUPLICITOUS,
];
