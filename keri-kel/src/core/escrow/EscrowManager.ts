import type { IEscrowStore, EscrowEntry } from "../../interfaces/IEscrowStore.js";
import type { IEventDatabase } from "../../interfaces/IEventDatabase.js";
import { EscrowReason, ESCROW_TIMEOUTS } from "../../types/EscrowReason.js";
import type { PendingEvent } from "../../types/PendingEvent.js";
import { ESCROW_PROCESSING_ORDER } from "./escrowTypes.js";

/** Metadata stored alongside an escrowed event. */
interface EscrowMeta {
  escrowedAt: number;
  sigsCollected: number;
  sigsNeeded: number;
  witsCollected: number;
  witsNeeded: number;
}

/**
 * EscrowManager — Lifecycle coordinator for escrowed events.
 *
 * Manages adding/removing events from escrow,
 * tracks metadata, and processes escrows in the correct order.
 */
export class EscrowManager {
  private store: IEscrowStore;
  private db: IEventDatabase;
  private meta = new Map<string, EscrowMeta>();

  constructor(store: IEscrowStore, db: IEventDatabase) {
    this.store = store;
    this.db = db;
  }

  private metaKey(prefix: string, said: string): string {
    return `${prefix}:${said}`;
  }

  /**
   * Add an event to escrow with a reason.
   */
  async escrow(
    reason: EscrowReason,
    prefix: string,
    sn: number,
    said: string,
    meta?: Partial<EscrowMeta>,
  ): Promise<void> {
    await this.store.add(reason, prefix, sn, said);
    this.meta.set(this.metaKey(prefix, said), {
      escrowedAt: meta?.escrowedAt ?? Date.now(),
      sigsCollected: meta?.sigsCollected ?? 0,
      sigsNeeded: meta?.sigsNeeded ?? 0,
      witsCollected: meta?.witsCollected ?? 0,
      witsNeeded: meta?.witsNeeded ?? 0,
    });
  }

  /**
   * Remove an event from escrow (when resolved or timed out).
   */
  async resolve(
    reason: EscrowReason,
    prefix: string,
    sn: number,
    said: string,
  ): Promise<void> {
    await this.store.remove(reason, prefix, sn, said);
    this.meta.delete(this.metaKey(prefix, said));
  }

  /**
   * Get all pending events for an identifier.
   */
  async pendingFor(identifier: string): Promise<PendingEvent[]> {
    const results: PendingEvent[] = [];
    for (const reason of Object.values(EscrowReason)) {
      const entries = await this.store.getByPrefix(reason, identifier);
      for (const entry of entries) {
        results.push(this.toPendingEvent(entry, reason));
      }
    }
    return results;
  }

  /**
   * Get all pending events with a specific reason.
   */
  async pendingByReason(reason: EscrowReason): Promise<PendingEvent[]> {
    const results: PendingEvent[] = [];
    for await (const entry of this.store.iterate(reason)) {
      results.push(this.toPendingEvent(entry, reason));
    }
    return results;
  }

  /**
   * Check if an event is pending for an identifier at a sequence number.
   */
  async isPending(identifier: string, sn: number): Promise<boolean> {
    for (const reason of Object.values(EscrowReason)) {
      const entries = await this.store.getByPrefix(reason, identifier);
      if (entries.some((e) => e.sn === sn)) return true;
    }
    return false;
  }

  /**
   * Process all escrows in the correct order.
   * Calls the provided callback for each escrowed event.
   * Returns the list of resolved entries.
   */
  async processEscrows(
    processOne: (
      reason: EscrowReason,
      entry: EscrowEntry,
    ) => Promise<boolean>,
  ): Promise<EscrowEntry[]> {
    const resolved: EscrowEntry[] = [];
    const now = Date.now();

    for (const reason of ESCROW_PROCESSING_ORDER) {
      const timeout = ESCROW_TIMEOUTS[reason];
      const toRemove: Array<{ reason: EscrowReason; entry: EscrowEntry }> = [];

      for await (const entry of this.store.iterate(reason)) {
        const meta = this.meta.get(this.metaKey(entry.prefix, entry.said));
        const escrowedAt = meta?.escrowedAt ?? now;

        // Check timeout
        if (now - escrowedAt > timeout) {
          toRemove.push({ reason, entry });
          continue;
        }

        // Try to process
        const success = await processOne(reason, entry);
        if (success) {
          resolved.push(entry);
          toRemove.push({ reason, entry });
        }
      }

      // Remove resolved/timed-out entries
      for (const { reason: r, entry: e } of toRemove) {
        await this.resolve(r, e.prefix, e.sn, e.said);
      }
    }

    return resolved;
  }

  private toPendingEvent(entry: EscrowEntry, reason: EscrowReason): PendingEvent {
    const meta = this.meta.get(this.metaKey(entry.prefix, entry.said));
    const now = Date.now();
    const escrowedAt = meta?.escrowedAt ?? now;
    const timeout = ESCROW_TIMEOUTS[reason];

    return {
      event: new Uint8Array(0), // Caller can fetch from db if needed
      prefix: entry.prefix,
      sn: entry.sn,
      said: entry.said,
      reason,
      escrowedAt,
      signaturesCollected: meta?.sigsCollected ?? 0,
      signaturesNeeded: meta?.sigsNeeded ?? 0,
      witnessesCollected: meta?.witsCollected ?? 0,
      witnessesNeeded: meta?.witsNeeded ?? 0,
      isExpired: now - escrowedAt > timeout,
    };
  }
}
