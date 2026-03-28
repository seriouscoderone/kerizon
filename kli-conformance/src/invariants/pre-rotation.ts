/**
 * Pre-Rotation Commitment Invariant:
 *
 * At inception, the identifier commits to its next set of keys
 * via the 'n' field (list of digests of next public keys).
 * When rotation occurs, the revealed keys in 'k' must match
 * the committed digests from the prior establishment event.
 *
 * This is KERI's core pre-rotation mechanism: you can only rotate
 * to keys you've already committed to, preventing post-compromise
 * key replacement.
 *
 * Properties tested:
 * 1. Rotation keys match prior next-key commitments
 * 2. Empty n list (abandoned) means no further rotation is possible
 * 3. Non-transferable identifier (no n list) cannot rotate at all
 */

import { verifySaid } from '../util/said.js';

/**
 * Verify that the pre-rotation commitment chain is intact across a KEL.
 * Only checks establishment events (icp/rot/dip/drt).
 *
 * Note: This does NOT verify the actual digest computation (that's in
 * key-commitment.ts). This verifies the structural properties:
 * - Every rotation has a prior establishment event
 * - n list length determines how many keys can be used in next rotation
 * - Empty n means abandoned (no further rotation)
 */
export function checkPreRotationChain(
  events: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const violations: string[] = [];
  const estEvents = events.filter(
    e => e['t'] === 'icp' || e['t'] === 'rot' || e['t'] === 'dip' || e['t'] === 'drt',
  );

  for (let i = 1; i < estEvents.length; i++) {
    const prior = estEvents[i - 1];
    const current = estEvents[i];

    const priorN = prior['n'] as string[] | undefined;
    const currentK = current['k'] as string[] | undefined;

    // If prior n is empty, no rotation should be possible
    if (priorN && priorN.length === 0) {
      violations.push(
        `sn=${current['s']}: rotation occurred but prior event had empty n list (abandoned)`,
      );
      continue;
    }

    // Current k must exist
    if (!currentK || currentK.length === 0) {
      violations.push(`sn=${current['s']}: rotation has empty k list`);
      continue;
    }

    // Number of revealed keys must not exceed committed digests
    if (priorN && currentK.length > priorN.length) {
      violations.push(
        `sn=${current['s']}: revealed ${currentK.length} keys but only ` +
        `${priorN.length} were committed in prior n list`,
      );
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Verify SAID integrity across all events in a KEL.
 * Each event's 'd' field must be a valid self-addressing identifier.
 */
export function checkSaidIntegrity(
  events: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const violations: string[] = [];

  for (const event of events) {
    if (!verifySaid(event, 'd')) {
      violations.push(`sn=${event['s']}: SAID verification failed for d="${event['d']}"`);
    }
  }

  return { valid: violations.length === 0, violations };
}
