import type { EscrowManager } from "../core/escrow/EscrowManager.js";
import type { EscrowReason } from "../types/EscrowReason.js";
import type { PendingEvent } from "../types/PendingEvent.js";

/**
 * Read-only escrow query interface.
 * Wraps EscrowManager for developer-friendly querying.
 */
export class EscrowQuery {
  private mgr: EscrowManager;

  constructor(mgr: EscrowManager) {
    this.mgr = mgr;
  }

  /** Get all escrowed events for an identifier. */
  async pendingFor(identifier: string): Promise<PendingEvent[]> {
    return this.mgr.pendingFor(identifier);
  }

  /** Get all escrowed events with a specific reason. */
  async pendingByReason(reason: EscrowReason): Promise<PendingEvent[]> {
    return this.mgr.pendingByReason(reason);
  }

  /** Check if any event is pending for an identifier at a sequence number. */
  async isPending(identifier: string, sequenceNumber: number): Promise<boolean> {
    return this.mgr.isPending(identifier, sequenceNumber);
  }
}
