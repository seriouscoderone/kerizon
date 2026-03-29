import type { DelegationSeal } from './types.js';

/**
 * Verify that a delegation seal matches the expected delegate event metadata.
 *
 * Compares the seal's prefix, sequence number (hex), and SAID against the
 * expected values. The sn is compared as hex strings.
 */
export function verifyDelegationSeal(
  seal: DelegationSeal,
  delegatePrefix: string,
  delegateSn: number,
  delegateSaid: string,
): boolean {
  return (
    seal.i === delegatePrefix &&
    seal.s === delegateSn.toString(16) &&
    seal.d === delegateSaid
  );
}

/**
 * Search through a delegator's events for a delegation seal that matches
 * the given delegate event metadata.
 *
 * Looks in each event's `a` (anchor) field for an object with matching
 * `i`, `s`, and `d` values.
 *
 * @returns the matching seal, or null if not found
 */
export function findDelegationSeal(
  delegatorEvents: Record<string, unknown>[],
  delegatePrefix: string,
  delegateSn: number,
  delegateSaid: string,
): DelegationSeal | null {
  const expectedSn = delegateSn.toString(16);

  for (const event of delegatorEvents) {
    const anchors = event['a'];
    if (!Array.isArray(anchors)) continue;

    for (const anchor of anchors) {
      if (
        typeof anchor === 'object' &&
        anchor !== null &&
        (anchor as Record<string, unknown>)['i'] === delegatePrefix &&
        (anchor as Record<string, unknown>)['s'] === expectedSn &&
        (anchor as Record<string, unknown>)['d'] === delegateSaid
      ) {
        return anchor as DelegationSeal;
      }
    }
  }

  return null;
}
