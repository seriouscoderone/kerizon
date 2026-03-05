import type { ICryptoProvider } from "../../interfaces/ICryptoProvider.js";
import { publicKeyBytesFromQb64 } from "./verifySigs.js";

/** An unindexed signature with its associated verfer. */
export interface CigarSig {
  /** qb64-encoded public key (verfer). */
  verferQb64: string;
  /** Raw signature bytes. */
  sigRaw: Uint8Array;
}

/**
 * Verify an unindexed (Cigar) signature.
 *
 * Cigars are verified directly: verfer.verify(sig, serialization).
 * Used for non-transferable witness receipts and external endorsements.
 */
export async function verifyCigar(
  crypto: ICryptoProvider,
  raw: Uint8Array,
  cigar: CigarSig,
): Promise<boolean> {
  const keyBytes = publicKeyBytesFromQb64(cigar.verferQb64);
  return crypto.verifySignature(keyBytes, cigar.sigRaw, raw);
}

/**
 * Verify multiple unindexed signatures, returning verified verfer qb64 strings.
 */
export async function verifyCigars(
  crypto: ICryptoProvider,
  raw: Uint8Array,
  cigars: CigarSig[],
): Promise<string[]> {
  const verified: string[] = [];
  for (const cigar of cigars) {
    if (await verifyCigar(crypto, raw, cigar)) {
      verified.push(cigar.verferQb64);
    }
  }
  return verified;
}
