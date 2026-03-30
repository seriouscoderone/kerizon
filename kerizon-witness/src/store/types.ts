export interface WitnessStore {
  putEvent(prefix: string, sn: number, said: string, raw: string, sigs: string[]): Promise<void>;
  getEvents(prefix: string): Promise<Array<{ sn: number; said: string; raw: string; sigs: string[] }>>;
  putKeyState(prefix: string, state: Record<string, unknown>): Promise<void>;
  getKeyState(prefix: string): Promise<Record<string, unknown> | null>;
  putReceipt(eventSaid: string, receipt: { signerAid: string; signature: string }): Promise<void>;
  getReceipts(eventSaid: string): Promise<Array<{ signerAid: string; signature: string }>>;
  putWitnessIdentity(signerQb64: string, prefix: string): Promise<void>;
  getWitnessIdentity(): Promise<{ signerQb64: string; prefix: string } | null>;
  close(): Promise<void>;
}
