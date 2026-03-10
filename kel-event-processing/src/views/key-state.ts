import type { KeyStateSnapshot, Threshold } from "../types.js";

/**
 * Read-only view over a KeyStateSnapshot.
 * Wraps cryptic field names with human-readable properties and
 * provides preparation helpers for building next events.
 */
export class KeyStateView {
  private readonly kss: KeyStateSnapshot;

  constructor(kss: KeyStateSnapshot) {
    this.kss = kss;
  }

  // -- Identity --
  get identifier(): string {
    return this.kss.i;
  }
  get sequenceNumber(): number {
    return parseInt(this.kss.s, 16);
  }
  get latestEventSaid(): string {
    return this.kss.d;
  }
  get priorEventSaid(): string {
    return this.kss.p;
  }

  // -- Signing --
  get signingKeys(): string[] {
    return this.kss.k;
  }
  get signingThreshold(): Threshold {
    return this.kss.kt;
  }

  // -- Pre-rotation --
  get nextKeyDigests(): string[] {
    return this.kss.n;
  }
  get nextKeyThreshold(): Threshold {
    return this.kss.nt;
  }

  // -- Witnesses --
  get witnesses(): string[] {
    return this.kss.b;
  }
  get witnessThreshold(): number {
    return parseInt(this.kss.bt, 16);
  }

  // -- Timestamps --
  get firstSeenOrdinal(): number {
    return parseInt(this.kss.f, 16);
  }
  get firstSeenDatetime(): string {
    return this.kss.dt;
  }

  // -- Delegation --
  get delegator(): string | undefined {
    return this.kss.di || undefined;
  }

  // -- Derived booleans --
  get isTransferable(): boolean {
    return this.kss.n.length > 0;
  }
  get isDelegated(): boolean {
    return !!this.kss.di;
  }
  get isEstablishmentOnly(): boolean {
    return this.kss.c.includes("EO");
  }
  get isDoNotDelegate(): boolean {
    return this.kss.c.includes("DND");
  }

  // -- Last establishment --
  get lastEstablishmentSn(): number {
    return parseInt(this.kss.ee.s, 16);
  }
  get lastEstablishmentSaid(): string {
    return this.kss.ee.d;
  }

  // -- Config --
  get configTraits(): string[] {
    return this.kss.c;
  }

  // -- Protocol version --
  get protocolVersion(): [number, number] {
    return this.kss.vn;
  }

  // -- Latest event type --
  get latestEventType(): string {
    return this.kss.et;
  }

  /** Get the underlying KeyStateSnapshot. */
  toSnapshot(): KeyStateSnapshot {
    return this.kss;
  }

  /**
   * Prepare configuration for a rotation event builder.
   * Returns the identifier context and previous event info
   * that a RotationBuilder needs.
   */
  prepareRotation(): {
    identifier: string;
    previousEvent: string;
    sequenceNumber: number;
    witnesses: string[];
  } {
    return {
      identifier: this.kss.i,
      previousEvent: this.kss.d,
      sequenceNumber: this.sequenceNumber + 1,
      witnesses: [...this.kss.b],
    };
  }

  /**
   * Prepare configuration for an interaction event builder.
   * Returns the identifier context and previous event info
   * that an InteractionBuilder needs.
   */
  prepareInteraction(): {
    identifier: string;
    previousEvent: string;
    sequenceNumber: number;
  } {
    return {
      identifier: this.kss.i,
      previousEvent: this.kss.d,
      sequenceNumber: this.sequenceNumber + 1,
    };
  }
}
