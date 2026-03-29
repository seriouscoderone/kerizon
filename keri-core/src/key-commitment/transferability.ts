/**
 * Transferability helpers for KERI identifiers.
 *
 * An identifier is transferable if its establishment event commits to
 * next rotation keys (non-empty `n` field). Certain prefix codes
 * denote non-transferable identifiers by convention.
 */

/** Non-transferable prefix codes (Ed25519N, ECDSA_256k1N, Ed448N, ECDSA_256r1N). */
const NON_TRANSFERABLE_CODES = new Set(['B', '1AAA', '1AAC', '1AAI']);

/**
 * Check whether an identifier is transferable based on its next-key digests.
 *
 * @param nextDigests - the `n` field from the establishment event
 * @returns true if there are committed rotation keys
 */
export function isTransferable(nextDigests: string[]): boolean {
  return nextDigests.length > 0;
}

/**
 * Check whether a prefix code denotes a transferable key type.
 *
 * @param prefixCode - the CESR code of the identifier prefix
 * @returns true if the code is for a transferable key type
 */
export function isTransferableCode(prefixCode: string): boolean {
  return !NON_TRANSFERABLE_CODES.has(prefixCode);
}
