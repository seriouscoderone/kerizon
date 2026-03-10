import type { KeyStateRecord } from "../types/KeyStateRecord.js";
import type { Threshold } from "../types/EventTypes.js";

/**
 * Read-only conceptual view over a KeyStateRecord/Kever.
 * Wraps cryptic field names with human-readable properties.
 */
export class KeyStateView {
  private ksr: KeyStateRecord;

  constructor(ksr: KeyStateRecord) {
    this.ksr = ksr;
  }

  // -- Identity --
  get identifier(): string { return this.ksr.i; }
  get sequenceNumber(): number { return parseInt(this.ksr.s, 16); }
  get latestEventSaid(): string { return this.ksr.d; }
  get priorEventSaid(): string { return this.ksr.p; }

  // -- Signing --
  get signingKeys(): string[] { return this.ksr.k; }
  get signingThreshold(): Threshold { return this.ksr.kt; }

  // -- Pre-rotation --
  get nextKeyDigests(): string[] { return this.ksr.n; }
  get nextKeyThreshold(): Threshold { return this.ksr.nt; }

  // -- Witnesses --
  get witnesses(): string[] { return this.ksr.b; }
  get witnessThreshold(): number { return parseInt(this.ksr.bt, 16); }

  // -- Timestamps --
  get firstSeenOrdinal(): number { return parseInt(this.ksr.f, 16); }
  get firstSeenDatetime(): string { return this.ksr.dt; }

  // -- Delegation --
  get delegator(): string | undefined {
    return this.ksr.di || undefined;
  }

  // -- Derived booleans --
  get isTransferable(): boolean { return this.ksr.n.length > 0; }
  get isDelegated(): boolean { return !!this.ksr.di; }
  get isEstablishmentOnly(): boolean { return this.ksr.c.includes("EO"); }
  get isDoNotDelegate(): boolean { return this.ksr.c.includes("DND"); }

  // -- Last establishment --
  get lastEstablishmentSn(): number { return parseInt(this.ksr.ee.s, 16); }
  get lastEstablishmentSaid(): string { return this.ksr.ee.d; }

  // -- Config --
  get configTraits(): string[] { return this.ksr.c; }

  /** Get the underlying KeyStateRecord. */
  toRecord(): KeyStateRecord { return this.ksr; }
}
