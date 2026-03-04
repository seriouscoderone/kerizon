import type { AID } from "./AID.js";
import type { Threshold } from "./Threshold.js";

/** The current key state for a KERI AID. */
export interface KeyState {
  /** qb64-encoded current public keys (one per key slot). */
  currentKeys: string[];
  /** Signing threshold — simple integer string or weighted fractional. */
  threshold: Threshold;
  /** Current sequence number of the key event log. */
  sn: bigint;
  /** AIDs of the current witness pool. */
  witnessAids: AID[];
}
