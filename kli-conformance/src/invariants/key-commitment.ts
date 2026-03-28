/**
 * Key Commitment (Pre-Rotation) Invariant:
 *
 * Property: For consecutive establishment events (e[j], e[j+1]):
 *   For each key K at index i in e[j+1].k:
 *     If i < len(e[j].n): digest(K) == e[j].n[i]
 *
 * This verifies the forward hash chain of pre-rotation:
 * the next key digests committed in event j must match
 * the actual keys revealed in event j+1.
 *
 * Note: This invariant only applies to establishment events (icp/rot/dip/drt).
 * Interaction events (ixn) don't change keys.
 */

import { digest, DIGEST_CODES } from '../util/hash.js';
import { CODE_TABLE, encodePrimitive } from '../util/cesr-codec.js';

/**
 * Verify that keys in the current event match the commitments in the prior event.
 *
 * @param priorNextDigests - The 'n' field from the prior establishment event
 * @param currentKeys - The 'k' field from the current establishment event
 * @returns Result with details of any mismatch
 */
export function checkKeyCommitment(
  priorNextDigests: string[],
  currentKeys: string[],
): { valid: boolean; violations: string[] } {
  const violations: string[] = [];

  const checkCount = Math.min(priorNextDigests.length, currentKeys.length);

  for (let i = 0; i < checkCount; i++) {
    const committedDigest = priorNextDigests[i];
    const revealedKey = currentKeys[i];

    // Determine the digest algorithm from the committed digest's CESR code
    const code = inferDigestCode(committedDigest);
    if (!code) {
      violations.push(`Index ${i}: cannot determine digest algorithm from "${committedDigest.substring(0, 4)}"`);
      continue;
    }

    // Compute digest of the revealed key
    const keyBytes = new TextEncoder().encode(revealedKey);
    const digestInfo = DIGEST_CODES[code];
    if (!digestInfo) {
      violations.push(`Index ${i}: unsupported digest code "${code}"`);
      continue;
    }

    const raw = digest(keyBytes, digestInfo.algo);
    const codeEntry = CODE_TABLE[code];
    const computed = encodePrimitive({ entry: codeEntry, raw });

    if (computed !== committedDigest) {
      violations.push(
        `Index ${i}: key "${revealedKey.substring(0, 8)}..." hashes to "${computed.substring(0, 8)}...", ` +
        `but committed digest is "${committedDigest.substring(0, 8)}..."`,
      );
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Extract all establishment events from a KEL and verify
 * the key commitment chain across them.
 */
export function checkKeyCommitmentChain(
  events: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const establishmentEvents = events.filter(
    e => e['t'] === 'icp' || e['t'] === 'rot' || e['t'] === 'dip' || e['t'] === 'drt',
  );

  const allViolations: string[] = [];

  for (let i = 1; i < establishmentEvents.length; i++) {
    const prior = establishmentEvents[i - 1];
    const current = establishmentEvents[i];

    const priorN = prior['n'] as string[];
    const currentK = current['k'] as string[];

    if (!priorN || !currentK) continue;

    const result = checkKeyCommitment(priorN, currentK);
    if (!result.valid) {
      const sn = current['s'] as string;
      allViolations.push(
        ...result.violations.map(v => `At sn=${sn}: ${v}`),
      );
    }
  }

  return { valid: allViolations.length === 0, violations: allViolations };
}

/** Infer the CESR digest code from the first character(s) of a digest string. */
function inferDigestCode(digestStr: string): string | null {
  if (digestStr.startsWith('0') && digestStr.length >= 2) {
    const c2 = digestStr.substring(0, 2);
    if (DIGEST_CODES[c2]) return c2;
  }
  const c1 = digestStr[0];
  if (DIGEST_CODES[c1]) return c1;
  return null;
}
