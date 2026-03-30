/**
 * Signature verification for KERI events.
 *
 * Verifies indexed signatures (Sigers) against public keys (Verfers)
 * and checks that the signing threshold is satisfied.
 */

import { Verfer, Tholder } from '@kerizon/cesr';
import type { Siger } from '@kerizon/cesr';

export interface SigVerificationResult {
  verified: boolean;
  verifiedIndices: number[];
  reason?: string;
}

/**
 * Verify indexed signatures against public keys and threshold.
 *
 * For each Siger, looks up the corresponding Verfer from the keys array
 * using siger.index, then calls verfer.verify(). Collects all verified
 * indices and checks them against the Tholder.
 *
 * @param raw - serialized event bytes (what was signed)
 * @param sigers - indexed signatures to verify
 * @param keys - qb64 public key strings (ordered by index)
 * @param threshold - signing threshold (hex string or weighted array)
 * @returns verification result with verified indices
 */
export async function verifySignatures(
  raw: Uint8Array,
  sigers: Siger[],
  keys: string[],
  threshold: string,
): Promise<SigVerificationResult> {
  if (sigers.length === 0) {
    return { verified: false, verifiedIndices: [], reason: 'no signatures provided' };
  }

  const verifiedIndices: number[] = [];

  for (const siger of sigers) {
    if (siger.index < 0 || siger.index >= keys.length) {
      continue; // skip out-of-range indices
    }
    const verfer = new Verfer({ qb64: keys[siger.index] });
    try {
      const valid = await verfer.verify(siger.raw, raw);
      if (valid) {
        verifiedIndices.push(siger.index);
      }
    } catch {
      // verification error — skip this siger
    }
  }

  const tholder = new Tholder({ sith: threshold });
  if (!tholder.satisfy(verifiedIndices)) {
    return {
      verified: false,
      verifiedIndices,
      reason: `threshold not satisfied: need ${threshold}, got indices [${verifiedIndices}]`,
    };
  }

  return { verified: true, verifiedIndices };
}
