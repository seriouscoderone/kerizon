import type { AID } from "../types/AID.js";
import type { KeyState } from "../types/KeyState.js";

/**
 * Key state resolution contract.
 * Consumers provide their own implementation (watcher pool, local KEL, etc.).
 */
export interface IKeyStateResolver {
  /**
   * Return the current key state for an AID, or null if unknown / unavailable.
   * Implementations may serve from a cache.
   */
  resolve(aid: AID): Promise<KeyState | null>;

  /**
   * Force a refresh from the underlying source and return the updated key state.
   * Returns null if the AID remains unavailable after the refresh.
   */
  refresh(aid: AID): Promise<KeyState | null>;
}
