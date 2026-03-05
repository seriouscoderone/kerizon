import type {
  IReceiptStore,
  NonTransReceipt,
  TransReceipt,
  ReceiptSet,
} from "../interfaces/IReceiptStore.js";

/** In-memory reference implementation of IReceiptStore. */
export class MemoryReceiptStore implements IReceiptStore {
  private nonTrans = new Map<string, NonTransReceipt[]>();
  private trans = new Map<string, TransReceipt[]>();

  private key(prefix: string, said: string): string {
    return `${prefix}:${said}`;
  }

  async putNonTransReceipt(
    prefix: string,
    said: string,
    receipt: NonTransReceipt,
  ): Promise<void> {
    const k = this.key(prefix, said);
    const existing = this.nonTrans.get(k) ?? [];
    if (
      !existing.some(
        (r) =>
          r.receiptorPrefix === receipt.receiptorPrefix &&
          r.sigQb64 === receipt.sigQb64,
      )
    ) {
      existing.push(receipt);
    }
    this.nonTrans.set(k, existing);
  }

  async putTransReceipt(
    prefix: string,
    said: string,
    receipt: TransReceipt,
  ): Promise<void> {
    const k = this.key(prefix, said);
    const existing = this.trans.get(k) ?? [];
    if (
      !existing.some(
        (r) =>
          r.receiptorPrefix === receipt.receiptorPrefix &&
          r.siger.qb64 === receipt.siger.qb64,
      )
    ) {
      existing.push(receipt);
    }
    this.trans.set(k, existing);
  }

  async getReceipts(prefix: string, said: string): Promise<ReceiptSet> {
    const k = this.key(prefix, said);
    return {
      nonTrans: this.nonTrans.get(k) ?? [],
      trans: this.trans.get(k) ?? [],
    };
  }
}
