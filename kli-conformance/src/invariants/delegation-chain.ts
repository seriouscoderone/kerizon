/**
 * Delegation Chain Invariant:
 *
 * For a delegated inception (dip) or delegated rotation (drt) to be valid:
 *   1. delegatee.di == delegator.prefix
 *   2. The delegator's KEL must contain an event (ixn or rot) with an anchor seal:
 *      {"i": delegatee.prefix, "s": delegatee.sn, "d": delegatee.said}
 *   3. Both the delegator's anchor and the delegatee's event must exist
 *
 * This is the "two-way peg" -- the delegatee claims a delegator (di field),
 * and the delegator confirms by anchoring a seal in their own KEL.
 */

export interface DelegationSeal {
  readonly i: string;  // delegatee prefix
  readonly s: string;  // delegatee sn (hex)
  readonly d: string;  // delegatee event SAID
}

/**
 * Extract delegation seals from an event's anchor data.
 * The 'a' field in ixn/rot events contains a list of seal objects.
 */
export function extractDelegationSeals(event: Record<string, unknown>): DelegationSeal[] {
  const anchors = event['a'] as Array<Record<string, unknown>> | undefined;
  if (!anchors) return [];

  return anchors
    .filter(a => typeof a['i'] === 'string' && typeof a['s'] === 'string' && typeof a['d'] === 'string')
    .map(a => ({
      i: a['i'] as string,
      s: a['s'] as string,
      d: a['d'] as string,
    }));
}

/**
 * Verify that a delegated event has correct delegation linkage.
 *
 * @param delegateeEvent - The dip or drt event
 * @param delegatorKel - The delegator's full KEL
 * @returns Validation result
 */
export function checkDelegationChain(
  delegateeEvent: Record<string, unknown>,
  delegatorKel: Array<Record<string, unknown>>,
): { valid: boolean; violation?: string } {
  const ilk = delegateeEvent['t'] as string;
  if (ilk !== 'dip' && ilk !== 'drt') {
    return { valid: true }; // not a delegated event
  }

  const di = delegateeEvent['di'] as string | undefined;
  if (!di) {
    return { valid: false, violation: 'Delegated event missing "di" field' };
  }

  const delegateePre = delegateeEvent['i'] as string;
  const delegateeSn = delegateeEvent['s'] as string;
  const delegateeSaid = delegateeEvent['d'] as string;

  // Check that di matches a prefix in the delegator's KEL
  const delegatorPre = (delegatorKel[0]?.['i'] as string) ?? '';
  if (di !== delegatorPre) {
    return {
      valid: false,
      violation: `di="${di}" does not match delegator prefix "${delegatorPre}"`,
    };
  }

  // Search delegator's KEL for an anchor seal matching the delegatee event
  for (const delegatorEvent of delegatorKel) {
    const seals = extractDelegationSeals(delegatorEvent);
    const match = seals.find(
      seal => seal.i === delegateePre && seal.s === delegateeSn && seal.d === delegateeSaid,
    );
    if (match) return { valid: true };
  }

  return {
    valid: false,
    violation: `No anchor seal found in delegator KEL for delegatee ` +
      `prefix=${delegateePre} sn=${delegateeSn} said=${delegateeSaid}`,
  };
}

/**
 * Verify bidirectional delegation peg.
 * Both the delegatee must reference the delegator (di field)
 * AND the delegator must anchor the delegatee (seal in a field).
 */
export function checkBidirectionalPeg(
  delegateeKel: Array<Record<string, unknown>>,
  delegatorKel: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const violations: string[] = [];

  for (const event of delegateeKel) {
    const ilk = event['t'] as string;
    if (ilk !== 'dip' && ilk !== 'drt') continue;

    const result = checkDelegationChain(event, delegatorKel);
    if (!result.valid) {
      violations.push(`sn=${event['s']}: ${result.violation}`);
    }
  }

  return { valid: violations.length === 0, violations };
}
