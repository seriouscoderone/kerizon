import type { ICryptoProvider } from "../../interfaces/ICryptoProvider.js";
import type { IndexedSiger } from "../signature/verifySigs.js";
import type { CigarSig } from "../signature/verifyCigar.js";
import { verifySigs } from "../signature/verifySigs.js";
import { verifyCigars } from "../signature/verifyCigar.js";

/** Result of witness signature verification. */
export interface WitnessVerifyResult {
  /** Unique verified witness indices (into the witness list). */
  verifiedWitnessIndices: number[];
  /** Count of unique verified witnesses. */
  count: number;
}

/**
 * Verify witness signatures for an event.
 *
 * Handles both:
 * - Indexed witness signatures (Sigers with index into witness list)
 * - Unindexed witness receipts (Cigars with verfer qb64)
 *
 * @param crypto - Crypto provider
 * @param raw - Event serialization bytes
 * @param witnessList - Current witness AID prefixes
 * @param wigers - Indexed witness signatures
 * @param cigars - Unindexed witness receipt couples
 * @returns Verified witness indices and count
 */
export async function verifyWitnessSigs(
  crypto: ICryptoProvider,
  raw: Uint8Array,
  witnessList: string[],
  wigers: IndexedSiger[] = [],
  cigars: CigarSig[] = [],
): Promise<WitnessVerifyResult> {
  const indexSet = new Set<number>();

  // Verify indexed witness signatures
  if (wigers.length > 0) {
    const result = await verifySigs(crypto, raw, wigers, witnessList);
    for (const idx of result.verifiedIndices) {
      indexSet.add(idx);
    }
  }

  // Verify unindexed (cigar) witness receipts
  if (cigars.length > 0) {
    const verifiedPrefixes = await verifyCigars(crypto, raw, cigars);
    for (const prefix of verifiedPrefixes) {
      const idx = witnessList.indexOf(prefix);
      if (idx >= 0) {
        indexSet.add(idx);
      }
    }
  }

  const verifiedWitnessIndices = Array.from(indexSet).sort((a, b) => a - b);
  return {
    verifiedWitnessIndices,
    count: verifiedWitnessIndices.length,
  };
}
