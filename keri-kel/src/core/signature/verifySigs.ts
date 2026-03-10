import { parseMatterFromText } from "cesr-ts";
import type { ICryptoProvider } from "../../interfaces/ICryptoProvider.js";

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

/** Result of signature verification. */
export interface VerifySigsResult {
  /** Sigers that verified successfully (deduplicated by index). */
  verifiedSigers: IndexedSiger[];
  /** Set of indices with verified signatures. */
  verifiedIndices: number[];
}

/**
 * Parse the raw public key bytes from a qb64-encoded verfer.
 */
export function publicKeyBytesFromQb64(qb64: string): Uint8Array {
  const encoded = new TextEncoder().encode(qb64);
  return parseMatterFromText(encoded).raw;
}

/**
 * Verify indexed signatures against an event serialization and a list of verfer qb64 keys.
 *
 * Algorithm (spec Section 3.3):
 * 1. Deduplicate sigers by qb64 representation
 * 2. For each siger: verify against the verfer at its index
 * 3. Deduplicate by index (first valid signature per index wins)
 */
export async function verifySigs(
  crypto: ICryptoProvider,
  raw: Uint8Array,
  sigers: IndexedSiger[],
  verferQb64s: string[],
): Promise<VerifySigsResult> {
  // Step 1: Deduplicate sigers by qb64
  const seen = new Set<string>();
  const unique: IndexedSiger[] = [];
  for (const siger of sigers) {
    if (!seen.has(siger.qb64)) {
      seen.add(siger.qb64);
      unique.push(siger);
    }
  }

  // Step 2: Verify each siger and deduplicate by index
  const indexMap = new Map<number, IndexedSiger>();
  for (const siger of unique) {
    if (siger.index >= verferQb64s.length) continue;
    if (indexMap.has(siger.index)) continue; // first valid per index wins

    const keyBytes = publicKeyBytesFromQb64(verferQb64s[siger.index]);
    const valid = await crypto.verifySignature(keyBytes, siger.raw, raw);
    if (valid) {
      indexMap.set(siger.index, siger);
    }
  }

  const verifiedSigers = Array.from(indexMap.values());
  const verifiedIndices = Array.from(indexMap.keys()).sort((a, b) => a - b);

  return { verifiedSigers, verifiedIndices };
}
