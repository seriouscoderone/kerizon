export type EscrowType = 'OOE' | 'PSE' | 'PWE' | 'PDE' | 'LDE' | 'Misfit';

export interface EscrowedEvent {
  readonly escrowType: EscrowType;
  readonly aid: string;
  readonly sn: number;
  readonly eventSaid: string;
  readonly escrowedAt: number;  // timestamp ms
}

export type ProcessResult =
  | { status: 'accepted'; aid: string; sn: number; said: string }
  | { status: 'duplicate'; aid: string; sn: number }
  | { status: 'escrowed'; escrowType: EscrowType; aid: string; sn: number; reason: string }
  | { status: 'rejected'; reason: string };
