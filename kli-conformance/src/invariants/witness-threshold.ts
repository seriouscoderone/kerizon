/**
 * Witness Threshold Invariant:
 *
 * Property: For any event with witnesses:
 *   len(b) >= bt   (enough witnesses to meet threshold)
 *   bt >= 0
 *   If bt > 0: the event requires at least bt witness receipts
 *
 * For rotation events:
 *   The new witness set = (prior witnesses - br) + ba
 *   len(new witnesses) >= bt
 */

/**
 * Verify witness threshold constraints on a single event.
 */
export function checkWitnessThreshold(event: Record<string, unknown>): {
  valid: boolean;
  violation?: string;
} {
  const bt = typeof event['bt'] === 'string'
    ? parseInt(event['bt'] as string, 16)
    : (event['bt'] as number ?? 0);

  if (bt < 0) {
    return { valid: false, violation: `bt is negative: ${bt}` };
  }

  const ilk = event['t'] as string;

  if (ilk === 'icp' || ilk === 'dip') {
    const witnesses = event['b'] as string[] ?? [];
    if (bt > witnesses.length) {
      return {
        valid: false,
        violation: `bt (${bt}) > witness count (${witnesses.length})`,
      };
    }
  }

  return { valid: true };
}

/**
 * Verify witness threshold across a rotation event given the prior witness set.
 */
export function checkRotationWitnessThreshold(
  priorWitnesses: string[],
  rotation: Record<string, unknown>,
): { valid: boolean; violation?: string } {
  const br = rotation['br'] as string[] ?? [];
  const ba = rotation['ba'] as string[] ?? [];
  const bt = typeof rotation['bt'] === 'string'
    ? parseInt(rotation['bt'] as string, 16)
    : (rotation['bt'] as number ?? 0);

  // New witness set = prior - removals + additions
  const remaining = priorWitnesses.filter(w => !br.includes(w));
  const newWitnesses = [...remaining, ...ba];

  if (bt > newWitnesses.length) {
    return {
      valid: false,
      violation: `After rotation: bt (${bt}) > new witness count (${newWitnesses.length})`,
    };
  }

  // Check no duplicate witnesses
  const unique = new Set(newWitnesses);
  if (unique.size !== newWitnesses.length) {
    return {
      valid: false,
      violation: `Duplicate witnesses after rotation`,
    };
  }

  return { valid: true };
}

/**
 * Check witness threshold constraints across an entire KEL.
 */
export function checkWitnessThresholdChain(
  events: Array<Record<string, unknown>>,
): { valid: boolean; violations: string[] } {
  const violations: string[] = [];
  let currentWitnesses: string[] = [];

  for (const event of events) {
    const ilk = event['t'] as string;

    if (ilk === 'icp' || ilk === 'dip') {
      const result = checkWitnessThreshold(event);
      if (!result.valid) violations.push(`sn=${event['s']}: ${result.violation}`);
      currentWitnesses = (event['b'] as string[]) ?? [];
    } else if (ilk === 'rot' || ilk === 'drt') {
      const result = checkRotationWitnessThreshold(currentWitnesses, event);
      if (!result.valid) violations.push(`sn=${event['s']}: ${result.violation}`);
      // Update witness set
      const br = event['br'] as string[] ?? [];
      const ba = event['ba'] as string[] ?? [];
      currentWitnesses = [...currentWitnesses.filter(w => !br.includes(w)), ...ba];
    }
    // ixn doesn't affect witnesses
  }

  return { valid: violations.length === 0, violations };
}
