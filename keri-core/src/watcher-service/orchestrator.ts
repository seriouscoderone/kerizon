/**
 * Watcher service orchestrator — cross-checks KEL copies from different
 * sources to detect duplicity (forks) and maintain duplicity event logs.
 */

import { detectFork } from '../evidence/detect.js';
import { DuplicityEventLog } from '../integrity/del.js';
import type { DuplicityStatus } from '../watcher/types.js';

export class WatcherService {
  private dels = new Map<string, DuplicityEventLog>();

  /**
   * Cross-check two KEL copies for the same AID.
   *
   * For each common sequence number, compares SAIDs. If different,
   * a fork is detected and recorded in the AID's duplicity event log.
   *
   * @returns DuplicityStatus indicating whether duplicity was found
   */
  crossCheck(
    aid: string,
    eventsA: Array<{ sn: number; said: string }>,
    eventsB: Array<{ sn: number; said: string }>,
  ): DuplicityStatus {
    const del = this.getDel(aid);
    const conflictingSaids: string[] = [];

    // Index eventsB by sequence number for efficient lookup
    const indexB = new Map<number, string>();
    for (const evt of eventsB) {
      indexB.set(evt.sn, evt.said);
    }

    // Compare each event in A against the corresponding event in B
    for (const evtA of eventsA) {
      const saidB = indexB.get(evtA.sn);
      if (saidB === undefined) continue;

      const fork = detectFork(
        { aid, sn: evtA.sn, said: evtA.said },
        { aid, sn: evtA.sn, said: saidB },
      );

      if (fork) {
        del.record({
          aid,
          sn: fork.sn,
          saidA: fork.firstSeenSaid,
          saidB: fork.conflictingSaid,
          detectedAt: new Date().toISOString(),
        });
        conflictingSaids.push(fork.firstSeenSaid, fork.conflictingSaid);
      }
    }

    return {
      aid,
      isDuplicitous: conflictingSaids.length >= 2,
      evidence: conflictingSaids,
    };
  }

  /**
   * Get the duplicity event log for an AID.
   *
   * Creates a new empty DEL if one does not already exist.
   */
  getDel(aid: string): DuplicityEventLog {
    let del = this.dels.get(aid);
    if (!del) {
      del = new DuplicityEventLog(aid);
      this.dels.set(aid, del);
    }
    return del;
  }

  /** Check if any duplicity is known for an AID. */
  hasDuplicity(aid: string): boolean {
    const del = this.dels.get(aid);
    return del !== undefined && del.hasDuplicity;
  }
}
