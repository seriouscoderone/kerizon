/** Base error for all KEL-related errors. */
export class KelError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KelError";
  }
}

/** Structural validation failure (field set, SAID binding, version string). */
export class StructuralError extends KelError {
  constructor(message: string) {
    super(message);
    this.name = "StructuralError";
  }
}

/** Sequence number validation failure. */
export class SequenceError extends KelError {
  constructor(message: string) {
    super(message);
    this.name = "SequenceError";
  }
}

/** Signature verification or threshold failure. */
export class SignatureError extends KelError {
  constructor(message: string) {
    super(message);
    this.name = "SignatureError";
  }
}

/** Pre-rotation commitment failure. */
export class PreRotationError extends KelError {
  constructor(message: string) {
    super(message);
    this.name = "PreRotationError";
  }
}

/** Different event (different SAID) at same sn. */
export class DuplicityError extends KelError {
  constructor(
    message: string,
    public readonly prefix: string,
    public readonly sn: number,
  ) {
    super(message);
    this.name = "DuplicityError";
  }
}

/** Event sn > expected next sn (gap in sequence). */
export class OutOfOrderError extends KelError {
  constructor(
    message: string,
    public readonly prefix: string,
    public readonly sn: number,
  ) {
    super(message);
    this.name = "OutOfOrderError";
  }
}

/** Delegation seal not found or DND violation. */
export class DelegationError extends KelError {
  constructor(message: string) {
    super(message);
    this.name = "DelegationError";
  }
}

/** Witness / TOAD validation failure. */
export class WitnessError extends KelError {
  constructor(message: string) {
    super(message);
    this.name = "WitnessError";
  }
}

/** Configuration trait violation (e.g., ixn with EO set). */
export class ConfigError extends KelError {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}
