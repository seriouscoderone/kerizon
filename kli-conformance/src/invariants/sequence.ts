/**
 * Sequence Number Monotonicity Invariant:
 *
 * Property: For any valid KEL:
 *   events[0].sn == 0
 *   forall i > 0: events[i].sn == events[i-1].sn + 1
 *
 * This is one of KERI's most fundamental invariants -- sequence numbers
 * must be strictly monotonically increasing with no gaps.
 */

import fc from 'fast-check';
import { arbKelSequence } from '../generators/events.js';

/** Check sn monotonicity on a list of parsed events. */
export function checkSequenceMonotonicity(
  events: Array<{ sn: number }>,
): { valid: boolean; violation?: string } {
  if (events.length === 0) return { valid: true };

  if (events[0].sn !== 0) {
    return { valid: false, violation: `First event sn is ${events[0].sn}, expected 0` };
  }

  for (let i = 1; i < events.length; i++) {
    if (events[i].sn !== events[i - 1].sn + 1) {
      return {
        valid: false,
        violation: `Event ${i}: sn is ${events[i].sn}, expected ${events[i - 1].sn + 1}`,
      };
    }
  }

  return { valid: true };
}

/** PBT property: generated KEL sequences always have monotonic sn. */
export const sequenceMonotonicityProperty = fc.property(
  arbKelSequence(1, 10),
  (events) => {
    const parsed = events.map(e => ({
      sn: typeof e['s'] === 'string' ? parseInt(e['s'] as string, 16) : 0,
    }));
    return checkSequenceMonotonicity(parsed).valid;
  },
);

/** PBT property: inception event always has sn == 0. */
export const inceptionSnZero = fc.property(
  arbKelSequence(0, 5),
  (events) => {
    const sn = typeof events[0]['s'] === 'string'
      ? parseInt(events[0]['s'] as string, 16)
      : -1;
    return sn === 0;
  },
);
