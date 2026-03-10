import type { IEventDatabase } from "../../interfaces/IEventDatabase.js";
import type { Kever } from "../state/Kever.js";
import { DelegationError } from "../../types/errors.js";
import type { EventSeal } from "../../types/Seals.js";

/**
 * Validate that a delegation seal exists in the delegator's KEL.
 *
 * For dip/drt events, the delegator must have anchored an EventSeal matching:
 * - seal.i == delegate's AID prefix
 * - seal.s == delegate event's sequence number (hex)
 * - seal.d == delegate event's SAID
 *
 * @param db - Event database for seal lookup
 * @param delegatorKever - The delegator's Kever (for DND check)
 * @param delegatePrefix - The delegate's AID prefix
 * @param delegateSn - The delegate event's sequence number
 * @param delegateSaid - The delegate event's SAID
 * @returns The delegator's anchoring event sn and said if found
 * @throws DelegationError if seal not found or DND violation
 */
export async function validateDelegation(
  db: IEventDatabase,
  delegatorKever: Kever | undefined,
  delegatePrefix: string,
  delegateSn: number,
  delegateSaid: string,
): Promise<{ delegatorSn: number; delegatorSaid: string } | undefined> {
  if (!delegatorKever) {
    // Delegator not yet known — cannot validate
    return undefined;
  }

  // DND check
  if (delegatorKever.doNotDelegate) {
    throw new DelegationError(
      `Delegator "${delegatorKever.prefix}" has DoNotDelegate (DND) trait set`,
    );
  }

  // Search the delegator's KEL for an anchoring seal
  // We search from sn=0 up to the delegator's current sn
  for (let sn = 0; sn <= delegatorKever.sn; sn++) {
    const saids = await db.getKelEntry(delegatorKever.prefix, sn);
    for (const said of saids) {
      const eventBytes = await db.getEvent(delegatorKever.prefix, said);
      if (!eventBytes) continue;

      try {
        const eventFields = JSON.parse(
          new TextDecoder().decode(eventBytes),
        ) as Record<string, unknown>;
        const anchors = eventFields.a as Array<Record<string, unknown>> | undefined;
        if (!anchors) continue;

        for (const seal of anchors) {
          if (
            seal.i === delegatePrefix &&
            seal.s === delegateSn.toString(16) &&
            seal.d === delegateSaid
          ) {
            return { delegatorSn: sn, delegatorSaid: said };
          }
        }
      } catch {
        // Skip unparseable events
      }
    }
  }

  // Seal not found
  return undefined;
}
