/**
 * Superseding rules per KERI spec (KID-0009 / Section 11.5).
 *
 * - A0: A pre-rotated rotation supersedes a non-pre-rotated rotation.
 * - A1: Two rotations both verified via pre-rotation — neither supersedes.
 * - A2: An interaction event can never supersede anything.
 * - Recovery: A rotation supersedes an interaction at the same sn.
 */
export enum SupersedingRule {
  /** No superseding relationship. */
  None = 'none',
  /** A0: pre-rotated rotation wins over non-pre-rotated rotation. */
  A0 = 'a0',
  /** Recovery: rotation supersedes interaction. */
  Recovery = 'recovery',
}

export interface SupersedingCandidate {
  readonly type: 'rot' | 'ixn';
  readonly sn: number;
  readonly preRotated: boolean;
}

/**
 * Determine whether `superseding` can supersede `superseded` and which rule applies.
 */
export function canSupersede(
  superseding: SupersedingCandidate,
  superseded: SupersedingCandidate,
): SupersedingRule {
  // A2: interaction events cannot supersede anything
  if (superseding.type === 'ixn') {
    return SupersedingRule.None;
  }

  // From here, superseding.type === 'rot'

  // Recovery: rotation supersedes interaction
  if (superseded.type === 'ixn') {
    return SupersedingRule.Recovery;
  }

  // Both are rotations — apply A0 / A1 rules
  // A0: pre-rotated superseding beats non-pre-rotated superseded
  if (superseding.preRotated && !superseded.preRotated) {
    return SupersedingRule.A0;
  }

  // A1: both pre-rotated, or neither, or superseded is pre-rotated
  // but superseding is not — no superseding
  return SupersedingRule.None;
}
