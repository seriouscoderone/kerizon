/**
 * KERL — Key Event Receipt Log.
 *
 * Tracks events and their receipts for a single identifier prefix,
 * providing the data layer for KAWA accountability checks.
 */

export interface ReceiptRef {
  /** AID of the witness or validator that signed the receipt. */
  signerAid: string;
  /** qb64 signature value. */
  signature: string;
}

interface ReceiptedEvent {
  said: string;
  sn: number;
  receipts: ReceiptRef[];
}

export class KERL {
  readonly prefix: string;

  /** Events indexed by sequence number. */
  private readonly eventsBySn = new Map<number, ReceiptedEvent>();
  /** Events indexed by SAID for receipt attachment. */
  private readonly eventsBySaid = new Map<string, ReceiptedEvent>();

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  /** Append a new event to the log with optional initial receipts. */
  appendEvent(said: string, sn: number, receipts: ReceiptRef[]): void {
    const entry: ReceiptedEvent = { said, sn, receipts: [...receipts] };
    this.eventsBySn.set(sn, entry);
    this.eventsBySaid.set(said, entry);
  }

  /** Add a receipt to an existing event identified by its SAID. */
  addReceipt(eventSaid: string, receipt: ReceiptRef): void {
    const entry = this.eventsBySaid.get(eventSaid);
    if (!entry) throw new Error(`no event with SAID ${eventSaid}`);
    entry.receipts.push(receipt);
  }

  /** Get all receipts for an event identified by its SAID. */
  getReceipts(eventSaid: string): ReceiptRef[] {
    const entry = this.eventsBySaid.get(eventSaid);
    if (!entry) return [];
    return entry.receipts;
  }

  /** Get the receipted event at a given sequence number, or undefined. */
  getReceiptedEvent(sn: number): { said: string; sn: number; receipts: ReceiptRef[] } | undefined {
    return this.eventsBySn.get(sn);
  }
}
