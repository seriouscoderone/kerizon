import type { DuplicityEvidence } from './types.js';

/**
 * Duplicity Event Log — append-only record of detected duplicity evidence
 * for a single AID.
 *
 * Each entry captures a pair of conflicting SAIDs at the same (aid, sn)
 * along with the detection timestamp.
 */
export class DuplicityEventLog {
  readonly aid: string;
  private readonly _entries: DuplicityEvidence[] = [];

  constructor(aid: string) {
    this.aid = aid;
  }

  /** Record a new duplicity evidence entry. */
  record(evidence: DuplicityEvidence): void {
    this._entries.push(evidence);
  }

  /** Snapshot of all recorded entries (defensive copy). */
  get entries(): readonly DuplicityEvidence[] {
    return [...this._entries];
  }

  /** Whether any duplicity has been detected for this AID. */
  get hasDuplicity(): boolean {
    return this._entries.length > 0;
  }
}
