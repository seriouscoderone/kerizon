import type { Threshold } from "./EventTypes.js";

/** Last establishment event info within a KeyStateRecord. */
export interface StateEstEvent {
  /** Sequence number of the last establishment event (hex). */
  s: string;
  /** SAID of the last establishment event. */
  d: string;
  /** Witnesses removed in last establishment event. */
  br: string[];
  /** Witnesses added in last establishment event. */
  ba: string[];
}

/**
 * Serializable snapshot of a Kever's key state.
 * Suitable for storage and transmission.
 */
export interface KeyStateRecord {
  /** Protocol version [major, minor]. */
  vn: [number, number];
  /** AID prefix qb64. */
  i: string;
  /** Sequence number (hex). */
  s: string;
  /** Prior event SAID. */
  p: string;
  /** Latest event SAID. */
  d: string;
  /** First-seen ordinal (hex). */
  f: string;
  /** ISO-8601 datetime of state update. */
  dt: string;
  /** Latest event type (ilk). */
  et: string;
  /** Current signing threshold. */
  kt: Threshold;
  /** Current signing keys qb64. */
  k: string[];
  /** Next rotation threshold. */
  nt: Threshold;
  /** Next key digests qb64. */
  n: string[];
  /** Witness threshold (hex). */
  bt: string;
  /** Current witness prefixes qb64. */
  b: string[];
  /** Configuration traits. */
  c: string[];
  /** Last establishment event info. */
  ee: StateEstEvent;
  /** Delegator prefix (empty string if not delegated). */
  di: string;
}
