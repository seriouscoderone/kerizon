/**
 * BLID (Blinded Identifier) computation for privacy-preserving identifiers.
 *
 * A BLID = digest(salt + sn) — deterministic but unlinkable without the salt.
 * Used to derive per-context identifiers that cannot be correlated across contexts.
 */

import { Diger } from '@kerizon/cesr';

/**
 * Compute a Blinded Identifier (BLID) from a shared secret salt and sequence number.
 * BLID = digest(salt + sn) — deterministic but unlinkable without the salt.
 */
export function computeBlid(salt: string, sn: number): string {
  const input = `${salt}${sn.toString(16).padStart(8, '0')}`;
  return Diger.digest(new TextEncoder().encode(input)).qb64;
}

/**
 * Derive a per-credential UUID from a shared secret salt and credential index.
 * Used for anti-correlation: each credential gets a unique UUID.
 */
export function deriveUuid(salt: string, index: number): string {
  const input = `${salt}uuid${index.toString(16).padStart(8, '0')}`;
  return Diger.digest(new TextEncoder().encode(input)).qb64;
}

/**
 * Verify a BLID matches a salt + sn combination.
 */
export function verifyBlid(blid: string, salt: string, sn: number): boolean {
  return computeBlid(salt, sn) === blid;
}
