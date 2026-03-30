/**
 * SAD path signatures — selective disclosure via field-level digests and aggregation.
 *
 * Compute digests over specific field paths in a Self-Addressed Data (SAD) structure,
 * then aggregate them into a single proof. Used for proving a field exists without
 * revealing the full document.
 */

import { Diger } from '@kerizon/cesr';

/**
 * Compute a SAD path digest — hash of a specific field path in a SAD.
 * Used for selective disclosure: prove a field exists without revealing the full document.
 */
export function computeSadPathDigest(
  sad: Record<string, unknown>,
  path: string[],
): string {
  let current: unknown = sad;
  for (const key of path) {
    if (typeof current !== 'object' || current === null) {
      throw new Error(`Invalid path: "${key}" not found`);
    }
    current = (current as Record<string, unknown>)[key];
  }
  const serialized = JSON.stringify(current);
  return Diger.digest(new TextEncoder().encode(serialized)).qb64;
}

/**
 * Compute an aggregate digest over multiple field digests.
 * The aggregate is the digest of the concatenated individual digests.
 */
export function computeAggregate(digests: string[]): string {
  const concatenated = digests.join('');
  return Diger.digest(new TextEncoder().encode(concatenated)).qb64;
}

/**
 * Verify an inclusion proof: does the field digest appear in the aggregate?
 * Simplified: recompute aggregate from all digests and compare.
 */
export function verifyInclusion(
  fieldDigest: string,
  allDigests: string[],
  expectedAggregate: string,
): boolean {
  const computed = computeAggregate(allDigests);
  return computed === expectedAggregate && allDigests.includes(fieldDigest);
}
