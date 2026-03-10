/** Behavioral configuration flags for the EventProcessor. */
export interface ProcessorConfig {
  /** When true, accept events for any AID prefix. Default: true */
  promiscuous: boolean;
  /** When true, treat events as local-sourced by default. Default: false */
  defaultLocal: boolean;
  /** When true, use attached timestamps from event attachments. Default: false */
  replayMode: boolean;
  /** When true, produce EventAccepted domain events. Default: true */
  directMode: boolean;
  /** When true, skip non-idempotent writes. Default: false */
  readOnly: boolean;
}

/** Default ProcessorConfig values. */
export const DEFAULT_PROCESSOR_CONFIG: ProcessorConfig = {
  promiscuous: true,
  defaultLocal: false,
  replayMode: false,
  directMode: true,
  readOnly: false,
};

/** Timeout values (in seconds) for each escrow type. */
export interface EscrowTimeouts {
  outOfOrder: number;
  partialSignatures: number;
  partialWitnesses: number;
  partialDelegation: number;
  delegable: number;
  misfitSource: number;
  unverifiedWitnessReceipt: number;
  unverifiedReceipt: number;
  unverifiedTransferableReceipt: number;
  likelyDuplicitous: number;
}

/** Default escrow timeout values in seconds. */
export const DEFAULT_ESCROW_TIMEOUTS: EscrowTimeouts = {
  outOfOrder: 1200,
  partialSignatures: 3600,
  partialWitnesses: 3600,
  partialDelegation: 3600,
  delegable: 3600,
  misfitSource: 3600,
  unverifiedWitnessReceipt: 3600,
  unverifiedReceipt: 3600,
  unverifiedTransferableReceipt: 3600,
  likelyDuplicitous: 3600,
};
