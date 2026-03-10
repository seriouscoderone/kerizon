import { parseMatterFromText } from "cesr-ts";
import type { KeyState } from "../types/KeyState.js";
import type { IndexedSig, CoupledSig } from "./AttachmentParser.js";

export interface ThresholdInput {
  indexedSigs: IndexedSig[];
  coupledSigs: CoupledSig[];
  message: Uint8Array;
  keyState: KeyState;
}

/** Parse the raw public key bytes from a qb64-encoded verfer. */
function publicKeyBytesFromQb64(qb64: string): Uint8Array {
  const encoded = new TextEncoder().encode(qb64);
  return parseMatterFromText(encoded).raw;
}

/** Verify a single Ed25519 signature using the Web Crypto API. */
async function verifyEd25519(
  publicKeyBytes: Uint8Array,
  signatureBytes: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  try {
    // Use .slice() to ensure ArrayBuffer backing (not SharedArrayBuffer)
    const key = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes.slice(),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      signatureBytes.slice(),
      message.slice(),
    );
  } catch {
    return false;
  }
}

/**
 * Rational number represented as numerator/denominator pair.
 * Used to avoid floating-point rounding errors in weighted threshold evaluation
 * as required by the KERI specification.
 */
interface Rational {
  num: bigint;
  den: bigint;
}

/** Parse a fraction string like "1/2" into a Rational. Whole numbers become n/1. */
function parseFraction(frac: string): Rational {
  const parts = frac.split("/");
  if (parts.length === 1) return { num: BigInt(parts[0]), den: 1n };
  const num = BigInt(parts[0]);
  const den = BigInt(parts[1]);
  return { num, den };
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
 * Evaluate whether the provided signatures satisfy the key state threshold.
 *
 * Supports:
 *   - Simple threshold: "N" (N-of-M integer string)
 *   - Weighted fractional threshold: string[][] where each group must sum >= 1.0
 *
 * Returns true if the threshold is met, false otherwise.
 */
export async function evaluateThreshold(
  input: ThresholdInput,
): Promise<boolean> {
  const { indexedSigs, coupledSigs, message, keyState } = input;
  const { currentKeys, threshold } = keyState;

  if (typeof threshold === "string") {
    const required = parseInt(threshold, 10);
    if (isNaN(required)) return false;

    let successCount = 0;

    for (const sig of indexedSigs) {
      if (sig.index >= currentKeys.length) continue;
      const keyBytes = publicKeyBytesFromQb64(currentKeys[sig.index]);
      if (await verifyEd25519(keyBytes, sig.raw, message)) {
        successCount++;
      }
    }

    for (const sig of coupledSigs) {
      if (await verifyEd25519(sig.verferRaw, sig.sigRaw, message)) {
        successCount++;
      }
    }

    return successCount >= required;
  } else {
    // Weighted threshold: threshold is string[][]
    // Flatten the groups to assign each key a (groupIdx, posIdx) coordinate.
    // For each signed key, check if its group reaches weight sum >= 1.0.

    // Build a flat index map: flatIdx → [groupIdx, posIdx]
    const flatMap: Array<[number, number]> = [];
    for (let g = 0; g < threshold.length; g++) {
      for (let p = 0; p < threshold[g].length; p++) {
        flatMap.push([g, p]);
      }
    }

    // Track successful (groupIdx, posIdx) pairs
    const successSet = new Set<string>();

    for (const sig of indexedSigs) {
      if (sig.index >= currentKeys.length || sig.index >= flatMap.length)
        continue;
      const keyBytes = publicKeyBytesFromQb64(currentKeys[sig.index]);
      if (await verifyEd25519(keyBytes, sig.raw, message)) {
        const [g, p] = flatMap[sig.index];
        successSet.add(`${g}:${p}`);
      }
    }

    // For coupled sigs, match against keys in currentKeys by public key value
    for (const sig of coupledSigs) {
      for (let i = 0; i < currentKeys.length && i < flatMap.length; i++) {
        const keyBytes = publicKeyBytesFromQb64(currentKeys[i]);
        if (await verifyEd25519(keyBytes, sig.sigRaw, message)) {
          const [g, p] = flatMap[i];
          successSet.add(`${g}:${p}`);
        }
      }
    }

    // Each group must independently reach weight sum >= 1 (using rational arithmetic)
    for (let g = 0; g < threshold.length; g++) {
      const group = threshold[g];
      let groupSum: Rational = { num: 0n, den: 1n };
      for (let p = 0; p < group.length; p++) {
        if (successSet.has(`${g}:${p}`)) {
          groupSum = rationalAdd(groupSum, parseFraction(group[p]));
        }
      }
      if (!rationalGte1(groupSum)) return false;
    }

    return true;
  }
}
