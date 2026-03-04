import type { AID } from "../types/AID.js";
import type { KeyState } from "../types/KeyState.js";
import type { IKeyStateResolver } from "../interfaces/IKeyStateResolver.js";

/**
 * In-memory mock implementation of IKeyStateResolver.
 *
 * Backed by a plain Map. Useful for tests and prototyping.
 * resolve() and refresh() both return from the in-memory map.
 */
export class MockKeyStateResolver implements IKeyStateResolver {
  private readonly store: Map<string, KeyState>;

  constructor(seed: Map<AID, KeyState> = new Map()) {
    this.store = new Map(seed);
  }

  async resolve(aid: AID): Promise<KeyState | null> {
    return this.store.get(aid) ?? null;
  }

  async refresh(aid: AID): Promise<KeyState | null> {
    return this.resolve(aid);
  }

  /** Add or overwrite a key state entry. */
  add(aid: AID, keyState: KeyState): void {
    this.store.set(aid, keyState);
  }

  /** Remove a key state entry. */
  remove(aid: AID): void {
    this.store.delete(aid);
  }
}
