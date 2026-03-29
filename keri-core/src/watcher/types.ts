export interface DuplicityStatus {
  readonly aid: string;
  readonly isDuplicitous: boolean;
  readonly evidence: string[];
}

export interface WatcherPort {
  queryKel(aid: string): Promise<unknown>;
  queryDuplicity(aid: string): Promise<DuplicityStatus>;
}

export function createDuplicityStatus(aid: string, conflictingSaids: string[]): DuplicityStatus {
  return { aid, isDuplicitous: conflictingSaids.length >= 2, evidence: conflictingSaids };
}
