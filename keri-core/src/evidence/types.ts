export interface ForkDetected {
  readonly aid: string;
  readonly sn: number;
  readonly firstSeenSaid: string;
  readonly conflictingSaid: string;
}
