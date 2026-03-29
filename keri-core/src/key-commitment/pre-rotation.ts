/**
 * Pre-rotation: next-key digest computation and verification.
 *
 * In KERI, rotation keys are committed to in advance by including
 * their digests in the prior establishment event's `n` field.
 * This module computes those digests and verifies them during rotation.
 */

import { Diger, MtrDex, resolveCode } from '@kerizon/cesr';

const textEncoder = new TextEncoder();

/**
 * Compute the next-key digest for a public key qb64.
 *
 * Digests the UTF-8 bytes of the full qb64 string (not the raw key bytes).
 *
 * @param keyQb64 - qb64-encoded public key
 * @param code    - digest algorithm code (default: 'E' / Blake3-256)
 * @returns the qb64 digest string
 */
export function computeNextDigest(
  keyQb64: string,
  code: string = MtrDex.Blake3_256,
): string {
  return Diger.digest(textEncoder.encode(keyQb64), code).qb64;
}

/**
 * Verify that rotation keys match prior next-key commitments.
 *
 * For each index in `min(newKeys.length, priorNextDigests.length)`,
 * re-computes the digest of the new key using the algorithm inferred
 * from the prior digest's code prefix, and compares.
 *
 * @param newKeys          - qb64 public keys from the rotation event
 * @param priorNextDigests - digest commitments from the prior establishment event
 * @returns bound (all match) and a list of mismatches with index, expected, got
 */
export function verifyPreRotation(
  newKeys: string[],
  priorNextDigests: string[],
): { bound: boolean; mismatches: Array<{ index: number; expected: string; got: string }> } {
  const mismatches: Array<{ index: number; expected: string; got: string }> = [];
  const len = Math.min(newKeys.length, priorNextDigests.length);

  for (let i = 0; i < len; i++) {
    const expected = priorNextDigests[i];
    const { code } = resolveCode(expected);
    const got = computeNextDigest(newKeys[i], code);
    if (got !== expected) {
      mismatches.push({ index: i, expected, got });
    }
  }

  return { bound: mismatches.length === 0, mismatches };
}
