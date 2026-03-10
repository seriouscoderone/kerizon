/** Base error for all validation-related errors. */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

/** Event sn > expected next sn (gap in sequence). → OOE escrow */
export class OutOfOrderError extends ValidationError {
  constructor(
    message: string,
    public readonly prefix: string,
    public readonly sn: number,
  ) {
    super(message);
    this.name = "OutOfOrderError";
  }
}

/** Controller signatures below signing threshold. → PSE escrow */
export class InsufficientSignaturesError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "InsufficientSignaturesError";
  }
}

/** Witness signatures below TOAD. → PWE escrow */
export class InsufficientWitnessesError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "InsufficientWitnessesError";
  }
}

/** Delegation seal not found in delegator's KEL. → PDE escrow */
export class MissingDelegationError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "MissingDelegationError";
  }
}

/** Local delegator has not yet anchored approval seal. → delegable escrow */
export class PendingDelegationApprovalError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "PendingDelegationApprovalError";
  }
}

/** Remote-sourced event for locally-controlled identifier. → MFE escrow */
export class ProvenanceMismatchError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "ProvenanceMismatchError";
  }
}

/** Witness receipt arrived before the receipted event. → UWE escrow */
export class UnverifiedWitnessReceiptError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "UnverifiedWitnessReceiptError";
  }
}

/** Non-transferable receipt arrived before the receipted event. → URE escrow */
export class UnverifiedReceiptError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "UnverifiedReceiptError";
  }
}

/** Transferable receipt arrived before the receipted event. → VRE escrow */
export class UnverifiedTransferableReceiptError extends ValidationError {
  constructor(message: string) {
    super(message);
    this.name = "UnverifiedTransferableReceiptError";
  }
}

/** Different event (different SAID) at same (prefix, sequence number). → LDE escrow */
export class DuplicitousEventError extends ValidationError {
  constructor(
    message: string,
    public readonly prefix: string,
    public readonly sn: number,
  ) {
    super(message);
    this.name = "DuplicitousEventError";
  }
}
