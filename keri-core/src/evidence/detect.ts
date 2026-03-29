import type { ForkDetected } from './types.js';

export interface EventRef {
  readonly aid: string;
  readonly sn: number;
  readonly said: string;
}

/**
 * Detect a fork (duplicity) between an accepted event and an incoming event.
 *
 * A fork exists when both events reference the same AID and sequence number
 * but have different SAIDs — indicating two conflicting events at the same
 * position in the KEL.
 *
 * @returns ForkDetected if a fork is found, null otherwise
 */
export function detectFork(
  accepted: EventRef,
  incoming: EventRef,
): ForkDetected | null {
  if (accepted.aid !== incoming.aid) return null;
  if (accepted.sn !== incoming.sn) return null;
  if (accepted.said === incoming.said) return null;

  return {
    aid: accepted.aid,
    sn: accepted.sn,
    firstSeenSaid: accepted.said,
    conflictingSaid: incoming.said,
  };
}

/**
 * Symmetric check: are two event references a fork?
 */
export function isForked(a: EventRef, b: EventRef): boolean {
  return detectFork(a, b) !== null;
}
