/**
 * First-Seen Ordering Invariant:
 *
 * KERI uses a "first seen" policy for event acceptance:
 * 1. For any given (prefix, sn) pair, only the first valid event is accepted
 * 2. Duplicate events at the same sn are rejected
 * 3. Events must arrive in order (no gaps allowed)
 *
 * This invariant is critical for preventing replay attacks and ensuring
 * all verifiers converge on the same key state.
 *
 * Properties:
 * - No two events in a KEL share the same sn
 * - No two events in a KEL share the same SAID
 * - Events are strictly ordered by sn
 * - Import of an already-seen event is idempotent (no state change)
 */

/**
 * Verify first-seen uniqueness across a KEL.
 * No two events may share the same (prefix, sn) pair.
 */
export function checkFirstSeenUniqueness(
  events: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const violations: string[] = [];
  const seen = new Map<string, string>(); // "prefix:sn" → said

  for (const event of events) {
    const prefix = event['i'] as string;
    const sn = event['s'] as string;
    const said = event['d'] as string;
    const key = `${prefix}:${sn}`;

    if (seen.has(key)) {
      violations.push(
        `Duplicate event at sn=${sn}: said1="${seen.get(key)}", said2="${said}"`,
      );
    } else {
      seen.set(key, said);
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Verify SAID uniqueness across a KEL.
 * Every event should have a unique SAID (since content differs).
 */
export function checkSaidUniqueness(
  events: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const violations: string[] = [];
  const seen = new Map<string, number>(); // said → sn

  for (const event of events) {
    const sn = typeof event['s'] === 'string'
      ? parseInt(event['s'] as string, 16)
      : (event['s'] as number);
    const said = event['d'] as string;

    if (seen.has(said)) {
      violations.push(
        `Duplicate SAID "${said}" at sn=${sn} and sn=${seen.get(said)}`,
      );
    } else {
      seen.set(said, sn);
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Verify strict ordering: events must be sorted by sn with no gaps.
 */
export function checkStrictOrdering(
  events: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const violations: string[] = [];

  for (let i = 0; i < events.length; i++) {
    const expectedSn = i;
    const actualSn = typeof events[i]['s'] === 'string'
      ? parseInt(events[i]['s'] as string, 16)
      : (events[i]['s'] as number);

    if (actualSn !== expectedSn) {
      violations.push(`Event at index ${i}: expected sn=${expectedSn}, got sn=${actualSn}`);
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Verify all first-seen invariants on a KEL.
 */
export function checkAllFirstSeenInvariants(
  events: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const allViolations: string[] = [];

  const uniqueness = checkFirstSeenUniqueness(events);
  allViolations.push(...uniqueness.violations);

  const saidUnique = checkSaidUniqueness(events);
  allViolations.push(...saidUnique.violations);

  const ordering = checkStrictOrdering(events);
  allViolations.push(...ordering.violations);

  return { valid: allViolations.length === 0, violations: allViolations };
}
