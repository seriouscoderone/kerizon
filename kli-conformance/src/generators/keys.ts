/**
 * fast-check arbitraries for KERI keys, thresholds, and witnesses.
 */

import fc from 'fast-check';
import { encodeB64 } from '../util/base64url.js';

/**
 * Generate a CESR-encoded Ed25519 public key (code 'D', 44 chars).
 * Format: "D" + base64url(0x00 + 32 random bytes)[1:]
 */
export const arbVerferQb64: fc.Arbitrary<string> = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .map(raw => {
    const padded = new Uint8Array(33);
    padded[0] = 0;
    padded.set(raw, 1);
    return 'D' + encodeB64(padded).slice(1);
  });

/**
 * Generate a CESR-encoded Blake3-256 digest (code 'E', 44 chars).
 */
export const arbDigestQb64: fc.Arbitrary<string> = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .map(raw => {
    const padded = new Uint8Array(33);
    padded[0] = 0;
    padded.set(raw, 1);
    return 'E' + encodeB64(padded).slice(1);
  });

/**
 * Generate a list of N Ed25519 public keys.
 */
export function arbKeyList(min: number = 1, max: number = 3): fc.Arbitrary<string[]> {
  return fc.array(arbVerferQb64, { minLength: min, maxLength: max });
}

/**
 * Generate a list of N Blake3-256 digests (for next key commitments).
 */
export function arbDigestList(min: number = 1, max: number = 3): fc.Arbitrary<string[]> {
  return fc.array(arbDigestQb64, { minLength: min, maxLength: max });
}

/**
 * Generate a simple signing threshold (hex string of an integer).
 * For keyCount keys, threshold is 1..keyCount.
 */
export function arbSimpleThreshold(keyCount: number): fc.Arbitrary<string> {
  return fc.integer({ min: 1, max: Math.max(1, keyCount) }).map(n => n.toString(16));
}

/**
 * Generate a witness AID (Ed25519 NT prefix, code 'B', 44 chars).
 */
export const arbWitnessAid: fc.Arbitrary<string> = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .map(raw => {
    const padded = new Uint8Array(33);
    padded[0] = 0;
    padded.set(raw, 1);
    return 'B' + encodeB64(padded).slice(1);
  });

/**
 * Generate a list of witness AIDs.
 */
export function arbWitnessList(min: number = 0, max: number = 3): fc.Arbitrary<string[]> {
  return fc.array(arbWitnessAid, { minLength: min, maxLength: max });
}
