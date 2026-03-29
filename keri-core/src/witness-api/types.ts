export type EventSubmissionResult =
  | { status: 'receipted'; eventSaid: string; receiptSignature: string }
  | { status: 'escrowed'; eventSaid: string; reason: string }
  | { status: 'rejected'; eventSaid: string; reason: string };

export interface KERLResponse {
  readonly aid: string;
  readonly events: Array<{ said: string; sn: number; receipted: boolean }>;
}

export interface WitnessServicePort {
  submitEvent(cesrMessage: Uint8Array): Promise<EventSubmissionResult>;
  getReceipt(prefix: string, sn?: number, said?: string): Promise<string>;
  queryKerl(prefix: string): Promise<KERLResponse>;
  resolveOobi(aid?: string, role?: string): Promise<Uint8Array>;
}
