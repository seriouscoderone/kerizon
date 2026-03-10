import { parseMatterFromText } from "cesr-ts";
import type { Threshold } from "./types.js";
import { ValidationError } from "./errors.js";

// ── Interfaces ──────────────────────────────────────────────────────

/** Abstraction for cryptographic operations. */
export interface CryptoProvider {
  /** Verify that a signature is valid for the given message and public key. */
  verifySignature(
    publicKeyBytes: Uint8Array,
    signatureBytes: Uint8Array,
    message: Uint8Array,
  ): Promise<boolean>;

  /** Compute a digest of the given data. */
  digest(data: Uint8Array, algorithm?: string): Promise<Uint8Array>;
}

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

/** An unindexed signature with its associated verfer. */
export interface CigarSig {
  /** qb64-encoded public key (verfer). */
  verferQb64: string;
  /** Raw signature bytes. */
  sigRaw: Uint8Array;
}

/** Result of signature verification. */
export interface VerifySigsResult {
  /** Sigers that verified successfully (deduplicated by index). */
  verifiedSigers: IndexedSiger[];
  /** Set of indices with verified signatures. */
  verifiedIndices: number[];
}

/** Result of witness signature verification. */
export interface WitnessVerifyResult {
  /** Unique verified witness indices (into the witness list). */
  verifiedWitnessIndices: number[];
  /** Count of unique verified witnesses. */
  count: number;
}

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Parse the raw public key bytes from a qb64-encoded verfer.
 */
export function publicKeyBytesFromQb64(qb64: string): Uint8Array {
  const encoded = new TextEncoder().encode(qb64);
  return parseMatterFromText(encoded).raw;
}

// ── Rational arithmetic (for weighted thresholds) ───────────────────

interface Rational {
  num: bigint;
  den: bigint;
}

function parseFraction(frac: string): Rational {
  const parts = frac.split("/");
  if (parts.length === 1) return { num: BigInt(parts[0]), den: 1n };
  return { num: BigInt(parts[0]), den: BigInt(parts[1]) };
}

function rationalAdd(a: Rational, b: Rational): Rational {
  return { num: a.num * b.den + b.num * a.den, den: a.den * b.den };
}

function rationalGte1(r: Rational): boolean {
  return r.num >= r.den;
}

// ── Signature verification ──────────────────────────────────────────

/**
 * Verify indexed signatures against an event serialization and a list of verfer qb64 keys.
 *
 * Algorithm (spec Section 3.3):
 * 1. Deduplicate sigers by qb64 representation
 * 2. For each siger: verify against the verfer at its index
 * 3. Deduplicate by index (first valid signature per index wins)
 */
export async function verifySigs(
  crypto: CryptoProvider,
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

/**
 * Check whether a set of verified signature indices satisfies a threshold.
 *
 * Supports:
 * - Simple (numeric) threshold: "N" — N-of-M integer string
 * - Weighted fractional threshold: string[][] — each clause must sum >= 1
 */
export function satisfyThreshold(
  threshold: Threshold,
  verifiedIndices: number[],
): boolean {
  const indexSet = new Set(verifiedIndices);

  if (typeof threshold === "string") {
    const required = parseInt(threshold, 10);
    if (isNaN(required)) return false;
    return indexSet.size >= required;
  }

  // Weighted fractional threshold: string[][]
  const flatMap: Array<[number, number]> = [];
  for (let g = 0; g < threshold.length; g++) {
    for (let p = 0; p < threshold[g].length; p++) {
      flatMap.push([g, p]);
    }
  }

  const clauseSums: Rational[] = threshold.map(() => ({ num: 0n, den: 1n }));

  for (const idx of indexSet) {
    if (idx >= flatMap.length) continue;
    const [g, p] = flatMap[idx];
    const weight = parseFraction(threshold[g][p]);
    clauseSums[g] = rationalAdd(clauseSums[g], weight);
  }

  return clauseSums.every(rationalGte1);
}

/**
 * Verify signatures and check threshold satisfaction.
 * Combines verifySigs + satisfyThreshold.
 */
export async function validateSigs(
  crypto: CryptoProvider,
  raw: Uint8Array,
  sigers: IndexedSiger[],
  verferQb64s: string[],
  threshold: Threshold,
): Promise<VerifySigsResult & { satisfied: boolean }> {
  const result = await verifySigs(crypto, raw, sigers, verferQb64s);
  const satisfied = satisfyThreshold(threshold, result.verifiedIndices);
  return { ...result, satisfied };
}

/** Compute the minimum number of keys required by a threshold. */
export function thresholdSize(threshold: Threshold): number {
  if (typeof threshold === "string") {
    return parseInt(threshold, 10) || 0;
  }
  return threshold.reduce((sum, clause) => sum + clause.length, 0);
}

// ── Witness sufficiency ─────────────────────────────────────────────

/**
 * Compute the default TOAD (Threshold of Accountable Duplicity).
 *
 * Algorithm (spec Section 6.2):
 * 1. f = max fault tolerance = floor((n - 1) / 3)
 * 2. Verify: n >= 3*f + 1
 * 3. m = ceil((n + f + 1) / 2)
 * 4. If weak: m = max(m, 1)
 */
export function ampleSufficient(
  n: number,
  f?: number,
  weak: boolean = true,
): number {
  if (n <= 0) return 0;

  if (f === undefined) {
    f = Math.floor((n - 1) / 3);
  }

  if (n < 3 * f + 1) {
    throw new ValidationError(
      `Insufficient witnesses (${n}) for fault tolerance (${f}): need at least ${3 * f + 1}`,
    );
  }

  let m = Math.ceil((n + f + 1) / 2);
  if (weak) {
    m = Math.max(m, 1);
  }

  return m;
}

// ── Pre-rotation verification ───────────────────────────────────────

/**
 * Verify pre-rotation commitments for a rotation event.
 *
 * For each verified siger:
 * 1. current_verfer = current_keys[siger.index]
 * 2. committed_diger = prior_next_digests[siger.ondex]
 * 3. Compute digest of current_verfer.qb64 using committed digest algorithm
 * 4. Verify digest matches committed_diger
 */
export async function verifyPreRotation(
  crypto: CryptoProvider,
  currentKeys: string[],
  priorNextDigests: string[],
  verifiedSigers: Array<{ index: number; ondex?: number }>,
): Promise<number[]> {
  const satisfiedIndices: number[] = [];

  for (const siger of verifiedSigers) {
    const ondex = siger.ondex ?? siger.index;
    if (ondex >= priorNextDigests.length) continue;
    if (siger.index >= currentKeys.length) continue;

    const verferQb64 = currentKeys[siger.index];
    const committedDigestQb64 = priorNextDigests[ondex];

    const committedRaw = publicKeyBytesFromQb64(committedDigestQb64);

    const verferBytes = new TextEncoder().encode(verferQb64);
    const computedDigest = await crypto.digest(verferBytes);

    if (
      computedDigest.length === committedRaw.length &&
      computedDigest.every((b, i) => b === committedRaw[i])
    ) {
      satisfiedIndices.push(siger.index);
    }
  }

  return satisfiedIndices;
}

// ── Cigar (unindexed) signature verification ────────────────────────

/** Verify an unindexed (Cigar) signature. */
export async function verifyCigar(
  crypto: CryptoProvider,
  raw: Uint8Array,
  cigar: CigarSig,
): Promise<boolean> {
  const keyBytes = publicKeyBytesFromQb64(cigar.verferQb64);
  return crypto.verifySignature(keyBytes, cigar.sigRaw, raw);
}

/** Verify multiple unindexed signatures, returning verified verfer qb64 strings. */
export async function verifyCigars(
  crypto: CryptoProvider,
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

// ── Witness signature verification ──────────────────────────────────

/**
 * Verify witness signatures for an event.
 *
 * Handles both indexed witness signatures (Sigers) and
 * unindexed witness receipts (Cigars).
 */
export async function verifyWitnessSigs(
  crypto: CryptoProvider,
  raw: Uint8Array,
  witnessList: string[],
  wigers: IndexedSiger[] = [],
  cigars: CigarSig[] = [],
): Promise<WitnessVerifyResult> {
  const indexSet = new Set<number>();

  if (wigers.length > 0) {
    const result = await verifySigs(crypto, raw, wigers, witnessList);
    for (const idx of result.verifiedIndices) {
      indexSet.add(idx);
    }
  }

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
