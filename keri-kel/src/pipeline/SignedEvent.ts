import type { IndexedSiger } from "../core/signature/verifySigs.js";

/** A built event ready to be signed. */
export interface BuiltEvent {
  /** Parsed event fields. */
  fields: Record<string, unknown>;
  /** Serialized event bytes. */
  raw: Uint8Array;
  /** AID prefix (from `i` field). */
  prefix: string;
  /** Event SAID (from `d` field). */
  said: string;
  /** Sequence number. */
  sn: number;
  /** Event ilk. */
  ilk: string;
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
    // Create a qb64 representation for dedup
    // Use btoa for browser/node compat instead of Buffer
    const binary = Array.from(sigBytes).map(b => String.fromCharCode(b)).join("");
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
