/**
 * Adapter classes that bridge PersistencePort (async) to
 * domain-specific interfaces (KeverStore, EscrowStore).
 *
 * PersistenceKeverStore: wraps PersistencePort as a sync KeverStore.
 *   Kevers are cached in memory for synchronous get/set calls required
 *   by processEvent(). Call flush() to persist pending changes.
 *
 * PersistenceEscrowStore: wraps PersistencePort for escrow operations.
 *   Escrows are cached in memory. Call flush() to persist, or load()
 *   to hydrate from the port.
 */

import type { Kever } from '../state/kever.js';
import type { KeverStore } from '../identity/process.js';
import type { EscrowedEvent } from '../identity/types.js';
import type { PersistencePort, SerializedKeyState } from './types.js';

// ── KeverStore adapter ──────────────────────────────────────────

/**
 * In-memory KeverStore backed by a PersistencePort.
 *
 * Synchronous get/set work against the cache. Pending key-state
 * writes are collected and written to the port on flush().
 */
export class PersistenceKeverStore implements KeverStore {
  private kevers = new Map<string, Kever>();
  private dirty = new Set<string>();
  private port: PersistencePort;

  constructor(port: PersistencePort) {
    this.port = port;
  }

  get(prefix: string): Kever | undefined {
    return this.kevers.get(prefix);
  }

  set(prefix: string, kever: Kever): void {
    this.kevers.set(prefix, kever);
    this.dirty.add(prefix);
  }

  getLastSaid(prefix: string): string | undefined {
    return this.kevers.get(prefix)?.lastEstSaid;
  }

  getExpectedSn(prefix: string): number {
    const k = this.kevers.get(prefix);
    return k ? k.sn + 1 : 0;
  }

  /** Persist all dirty kevers to the port. */
  async flush(): Promise<void> {
    const writes: Promise<void>[] = [];
    for (const prefix of this.dirty) {
      const kever = this.kevers.get(prefix);
      if (!kever) continue;
      const state: SerializedKeyState = {
        prefix: kever.prefix,
        sn: kever.sn,
        currentKeys: kever.currentKeys,
        signingThreshold: kever.signingThreshold,
        nextDigests: kever.nextDigests,
        nextThreshold: kever.nextThreshold,
        witnesses: kever.witnesses,
        witnessThreshold: kever.witnessThreshold,
        configTraits: kever.configTraits,
        transferable: kever.transferable,
        lastEstSn: kever.lastEstSn,
        lastEstSaid: kever.lastEstSaid,
        delegator: kever.delegator,
      };
      writes.push(this.port.putKeyState(prefix, state));
    }
    await Promise.all(writes);
    this.dirty.clear();
  }

  /** Seed a kever into the cache without marking dirty. */
  seed(prefix: string, kever: Kever): void {
    this.kevers.set(prefix, kever);
  }
}
