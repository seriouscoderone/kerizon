/**
 * @kerizon/watcher — watcher, integrity, and evidence domains.
 */

export { detectFork, isForked } from './evidence/detect.js';
export type { EventRef } from './evidence/detect.js';
export type { ForkDetected } from './evidence/types.js';

export { DuplicityEventLog } from './integrity/del.js';
export { SupersedingRule, canSupersede } from './integrity/superseding.js';
export type { SupersedingCandidate } from './integrity/superseding.js';
export type {
  DuplicityEvidence,
  SupersedingRecoveryEvent,
  DisputedBranch,
  TrustDecision,
} from './integrity/types.js';

export { createDuplicityStatus } from './status.js';
export type { DuplicityStatus, WatcherPort } from './status.js';

export { WatcherService } from './orchestrator.js';
