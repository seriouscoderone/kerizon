import { WitnessError } from "../../types/errors.js";

/**
 * Compute the default TOAD (Threshold of Accountable Duplicity).
 *
 * Algorithm (spec Section 6.2):
 * 1. If f not specified: f = max fault tolerance = floor((n - 1) / 3)
 * 2. Verify: n >= 3*f + 1 (Byzantine fault tolerance requirement)
 * 3. Compute: m = ceil((n + f + 1) / 2)
 * 4. If weak: m = max(m, 1) (at least 1 witness receipt)
 * 5. Return m
 *
 * @param n - Number of witnesses
 * @param f - Maximum faults to tolerate (default: floor((n-1)/3))
 * @param weak - If true, ensure at least 1 (default: true)
 * @returns Default TOAD value
 */
export function ample(n: number, f?: number, weak: boolean = true): number {
  if (n <= 0) return 0;

  if (f === undefined) {
    f = Math.floor((n - 1) / 3);
  }

  if (n < 3 * f + 1) {
    throw new WitnessError(
      `Insufficient witnesses (${n}) for fault tolerance (${f}): need at least ${3 * f + 1}`,
    );
  }

  let m = Math.ceil((n + f + 1) / 2);
  if (weak) {
    m = Math.max(m, 1);
  }

  return m;
}
