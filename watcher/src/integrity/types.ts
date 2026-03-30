export interface DuplicityEvidence {
  readonly aid: string;
  readonly sn: number;
  readonly saidA: string;
  readonly saidB: string;
  readonly detectedAt: string;
}

export interface SupersedingRecoveryEvent {
  readonly aid: string;
  readonly recoverySn: number;
  readonly forkPointSn: number;
}

export interface DisputedBranch {
  readonly aid: string;
  readonly forkSn: number;
  readonly branchSaids: string[];
}

export type TrustDecision =
  | { kind: 'trusted'; aid: string }
  | { kind: 'revoked'; aid: string; evidence: DuplicityEvidence }
  | { kind: 'reconciled'; aid: string; recoverySn: number };
