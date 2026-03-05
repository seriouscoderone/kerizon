import type { Threshold } from "../../types/EventTypes.js";

/**
 * Rational number represented as numerator/denominator pair.
 * Used to avoid floating-point rounding errors in weighted threshold evaluation.
 */
interface Rational {
  num: bigint;
  den: bigint;
}

/** Parse a fraction string like "1/2" into a Rational. Whole numbers become n/1. */
function parseFraction(frac: string): Rational {
  const parts = frac.split("/");
  if (parts.length === 1) return { num: BigInt(parts[0]), den: 1n };
  return { num: BigInt(parts[0]), den: BigInt(parts[1]) };
}

/** Add two rationals: a/b + c/d = (ad + bc) / bd */
function rationalAdd(a: Rational, b: Rational): Rational {
  return { num: a.num * b.den + b.num * a.den, den: a.den * b.den };
}

/** Check if a rational is >= 1 (i.e. num >= den). Assumes den > 0. */
function rationalGte1(r: Rational): boolean {
  return r.num >= r.den;
}

/**
 * Check whether a set of verified signature indices satisfies a threshold.
 *
 * Supports:
 * - Simple (numeric) threshold: "N" — N-of-M integer string
 * - Weighted fractional threshold: string[][] — each clause must sum >= 1
 *
 * This is an indices-only check — no crypto verification happens here.
 * Callers must first verify signatures and provide only verified indices.
 */
export function satisfyThreshold(
  threshold: Threshold,
  verifiedIndices: number[],
): boolean {
  const indexSet = new Set(verifiedIndices);

  if (typeof threshold === "string") {
    // Simple numeric threshold
    const required = parseInt(threshold, 10);
    if (isNaN(required)) return false;
    return indexSet.size >= required;
  }

  // Weighted fractional threshold: string[][]
  // Each clause (inner array) maps to a contiguous range of key positions.
  // All clauses must independently reach weight sum >= 1.

  // Build flat index map: flatIdx → [clauseIdx, posIdx]
  const flatMap: Array<[number, number]> = [];
  for (let g = 0; g < threshold.length; g++) {
    for (let p = 0; p < threshold[g].length; p++) {
      flatMap.push([g, p]);
    }
  }

  // Track satisfied positions per clause
  const clauseSums: Rational[] = threshold.map(() => ({ num: 0n, den: 1n }));

  for (const idx of indexSet) {
    if (idx >= flatMap.length) continue;
    const [g, p] = flatMap[idx];
    const weight = parseFraction(threshold[g][p]);
    clauseSums[g] = rationalAdd(clauseSums[g], weight);
  }

  // Every clause must reach >= 1
  return clauseSums.every(rationalGte1);
}

/**
 * Compute the minimum number of keys required by a threshold.
 */
export function thresholdSize(threshold: Threshold): number {
  if (typeof threshold === "string") {
    return parseInt(threshold, 10) || 0;
  }
  // For weighted: total number of positions across all clauses
  return threshold.reduce((sum, clause) => sum + clause.length, 0);
}
