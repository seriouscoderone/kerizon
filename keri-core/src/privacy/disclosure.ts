/**
 * Privacy disclosure classification and validation.
 *
 * Classifies ACDC privacy levels based on the `u` (UUID nonce) field,
 * and validates compact-vs-expanded disclosure consistency.
 */

import type { PrivacyLevel } from './types.js';

/**
 * Classify the privacy level of an ACDC.
 *
 * - If `u` field is present and non-empty string -> 'private'
 * - If `u` field is present but empty string -> 'metadata'
 * - If `u` field is absent -> 'public'
 */
export function classifyPrivacyLevel(acdc: Record<string, unknown>): PrivacyLevel {
  if (!('u' in acdc)) {
    return 'public';
  }

  const u = acdc['u'];
  if (typeof u === 'string' && u.length > 0) {
    return 'private';
  }

  return 'metadata';
}

/**
 * Validate that a compact ACDC disclosure matches an expanded disclosure.
 *
 * Simplified check: verifies that the SAID (d field) of the compact form
 * matches the SAID of the expanded form. A real implementation would also
 * verify selective disclosure proofs and attribute digests.
 */
export function validateDisclosure(
  compact: Record<string, unknown>,
  expanded: Record<string, unknown>,
): boolean {
  const compactSaid = compact['d'];
  const expandedSaid = expanded['d'];

  if (!compactSaid || !expandedSaid) {
    return false;
  }

  return compactSaid === expandedSaid;
}
