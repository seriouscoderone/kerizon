/** An indexed signature for verification. */
export interface IndexedSiger {
  /** Zero-based index into the current signing key list. */
  index: number;
  /** Optional other index for pre-rotation mapping. */
  ondex?: number;
  /** Raw signature bytes. */
  raw: Uint8Array;
  /** qb64 representation (used for deduplication). */
  qb64: string;
}

/** A signer that can produce a signature for a message. */
export interface Signer {
  /** Zero-based index into the key list. */
  index: number;
  /** Optional ondex for rotation events. */
  ondex?: number;
  /** Sign the message, returning raw signature bytes. */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** A built event ready to be signed. */
export class BuiltEvent {
  /** Parsed event fields. */
  readonly fields: Record<string, unknown>;
  /** Serialized event bytes. */
  readonly raw: Uint8Array;
  /** AID prefix (from `i` field). */
  readonly prefix: string;
  /** Event SAID (from `d` field). */
  readonly said: string;
  /** Sequence number. */
  readonly sn: number;
  /** Event ilk. */
  readonly ilk: string;
  /** Controller indexed signatures. */
  readonly sigers: IndexedSiger[] = [];
  /** Witness indexed signatures. */
  readonly witnessSignatures: IndexedSiger[] = [];
  /** Receipt couples (non-transferable). */
  readonly receiptCouples: Array<{ prefix: string; signature: Uint8Array }> = [];

  constructor(init: {
    fields: Record<string, unknown>;
    raw: Uint8Array;
    prefix: string;
    said: string;
    sn: number;
    ilk: string;
  }) {
    this.fields = init.fields;
    this.raw = init.raw;
    this.prefix = init.prefix;
    this.said = init.said;
    this.sn = init.sn;
    this.ilk = init.ilk;
  }

  /** Sign this event with one or more signers, appending to controller sigers. */
  async signWith(signers: Signer[]): Promise<this> {
    for (const signer of signers) {
      const sigBytes = await signer.sign(this.raw);
      const binary = Array.from(sigBytes)
        .map((b) => String.fromCharCode(b))
        .join("");
      const qb64 = `sig_${signer.index}_${btoa(binary)}`;
      this.sigers.push({
        index: signer.index,
        ondex: signer.ondex,
        raw: sigBytes,
        qb64,
      });
    }
    return this;
  }
}

/** A built event with attached signatures. */
export interface SignedEvent {
  /** The underlying built event. */
  event: BuiltEvent;
  /** Indexed signatures. */
  sigers: IndexedSiger[];
}

/**
 * Sign a built event with one or more signers.
 * Returns a SignedEvent with the signatures attached.
 */
export async function signEvent(
  event: BuiltEvent,
  signers: Signer[],
): Promise<SignedEvent> {
  const sigers: IndexedSiger[] = [];

  for (const signer of signers) {
    const sigBytes = await signer.sign(event.raw);
    const binary = Array.from(sigBytes)
      .map((b) => String.fromCharCode(b))
      .join("");
    const qb64 = `sig_${signer.index}_${btoa(binary)}`;
    sigers.push({
      index: signer.index,
      ondex: signer.ondex,
      raw: sigBytes,
      qb64,
    });
  }

  return { event, sigers };
}
