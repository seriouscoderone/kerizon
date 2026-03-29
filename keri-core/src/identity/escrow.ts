import type { EscrowedEvent, EscrowType } from './types.js';

export class EscrowStore {
  private entries: EscrowedEvent[] = [];

  add(event: EscrowedEvent): void {
    this.entries.push(event);
  }

  drain(aid: string, sn: number): EscrowedEvent[] {
    const matching = this.entries.filter(e => e.aid === aid && e.sn === sn);
    this.entries = this.entries.filter(e => !(e.aid === aid && e.sn === sn));
    return matching;
  }

  getByType(type: EscrowType): ReadonlyArray<EscrowedEvent> {
    return this.entries.filter(e => e.escrowType === type);
  }

  sweepTimeout(maxAgeMs: number): EscrowedEvent[] {
    const now = Date.now();
    const expired = this.entries.filter(e => now - e.escrowedAt > maxAgeMs);
    this.entries = this.entries.filter(e => now - e.escrowedAt <= maxAgeMs);
    return expired;
  }

  get size(): number { return this.entries.length; }
}
