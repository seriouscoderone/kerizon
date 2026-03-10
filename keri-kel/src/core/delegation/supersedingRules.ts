import { Ilk } from "../../types/EventTypes.js";

/**
 * Check if a rotation event is a valid recovery attempt
 * according to the superseding rules.
 *
 * Non-Delegated (A-rules):
 * - A rot at sn supersedes an ixn at the same sn if lastEst.s < sn <= kever.sn
 * - A rot MUST NOT supersede another rot at the same sn (Rule A1)
 * - An ixn MUST NOT supersede any event (Rule A2)
 *
 * Delegated (B-rules):
 * - A drt at sn supersedes an ixn at the same sn if lastEst.s <= sn <= kever.sn
 * - A drt can supersede a prior drt if delegator seal is later (B1-B3)
 *
 * @param ilk - The event type being processed
 * @param sn - The event's sequence number
 * @param keverSn - Current kever sequence number
 * @param lastEstSn - Sequence number of the last establishment event
 * @param currentIlkAtSn - The ilk of the event currently at this sn (if any)
 * @returns true if this is a valid superseding event
 */
export function isValidSupersede(
  ilk: string,
  sn: number,
  keverSn: number,
  lastEstSn: number,
  currentIlkAtSn?: string,
): boolean {
  if (ilk === Ilk.ixn) {
    // Rule A2: ixn MUST NOT supersede any event
    return false;
  }

  if (ilk === Ilk.rot) {
    // A-rules (non-delegated)
    // Rule A0: rot supersedes ixn at same sn if lastEst.s < sn <= kever.sn
    if (lastEstSn < sn && sn <= keverSn) {
      // Rule A1: rot MUST NOT supersede another rot
      if (currentIlkAtSn === Ilk.rot) return false;
      return true;
    }
    return false;
  }

  if (ilk === Ilk.drt) {
    // B-rules (delegated)
    // Rule B0: drt at sn supersedes if lastEst.s <= sn <= kever.sn
    // (note: <= for delegated, not < like for rot)
    if (lastEstSn <= sn && sn <= keverSn) {
      return true;
    }
    return false;
  }

  return false;
}

/**
 * For delegated superseding (B1-B3), compare two delegation seals
 * to determine which takes precedence.
 *
 * @param newSealDelegatorSn - Delegator sn of the new event's seal
 * @param newSealDelegatorSaid - Delegator said of the new event's seal
 * @param oldSealDelegatorSn - Delegator sn of the existing event's seal
 * @param oldSealDelegatorSaid - Delegator said of the existing event's seal
 * @returns true if the new seal supersedes the old seal
 */
export function delegationSealSupersedes(
  newSealDelegatorSn: number,
  newSealDelegatorSaid: string,
  oldSealDelegatorSn: number,
  oldSealDelegatorSaid: string,
): boolean {
  // B1: New seal in later delegator event (higher sn)
  if (newSealDelegatorSn > oldSealDelegatorSn) return true;

  // B2/B3: Same sn but different events — requires additional context
  // (seal index position, event ilk). For simplicity, if the SAID differs
  // and sn is the same, the caller must provide additional context.
  // Basic rule: if sn is equal and SAIDs differ, we need external info.
  // Default to not superseding.
  return false;
}
