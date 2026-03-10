import { Ilk } from "../../types/EventTypes.js";

/**
 * Field order definitions per ilk (v1.0).
 * Fields MUST appear in this exact order.
 */
export const EVENT_FIELD_ORDER: Record<string, readonly string[]> = {
  [Ilk.icp]: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
  [Ilk.rot]: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
  [Ilk.ixn]: ["v", "t", "d", "i", "s", "p", "a"],
  [Ilk.dip]: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
  [Ilk.drt]: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
  [Ilk.rct]: ["v", "t", "d", "i", "s"],
};

/** Fields that are SAID-computed for each ilk. */
export const SAID_FIELDS: Record<string, readonly string[]> = {
  [Ilk.icp]: ["d", "i"],
  [Ilk.rot]: ["d"],
  [Ilk.ixn]: ["d"],
  [Ilk.dip]: ["d", "i"],
  [Ilk.drt]: ["d"],
  [Ilk.rct]: [],
};

/** Fields that are required for each ilk — same as field order for strict mode. */
export const REQUIRED_FIELDS = EVENT_FIELD_ORDER;
