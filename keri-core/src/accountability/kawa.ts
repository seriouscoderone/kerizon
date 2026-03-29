/**
 * KAWA — KERI Agreement Algorithm for Witness Accountability.
 *
 * Provides threshold checking (checkAccountability) and the ample()
 * function that computes the minimum acceptable receipt threshold
 * for a given witness pool size, satisfying Byzantine fault tolerance.
 */

export interface AccountabilityResult {
  met: boolean;
  count: number;
  threshold: number;
}

/**
 * Check whether receipt count meets the accountability threshold (toad).
 */
export function checkAccountability(receiptCount: number, toad: number): AccountabilityResult {
  return {
    met: receiptCount >= toad,
    count: receiptCount,
    threshold: toad,
  };
}

/**
 * Compute the minimum acceptable toad for a witness pool of size n.
 *
 * Formula: ceil((n + 1 + floor((n-1)/3)) / 2)
 *
 * This guarantees that the threshold exceeds the maximum number of
 * Byzantine-faulty witnesses (floor((n-1)/3)), providing immune
 * agreement.
 */
export function ample(n: number): number {
  return Math.ceil((n + 1 + Math.floor((n - 1) / 3)) / 2);
}
