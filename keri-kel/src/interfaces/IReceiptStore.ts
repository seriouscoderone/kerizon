/** A non-transferable receipt (witness prefix + cigar). */
export interface NonTransReceipt {
  /** Receiptor (witness) prefix qb64. */
  receiptorPrefix: string;
  /** Raw signature bytes. */
  sigRaw: Uint8Array;
  /** qb64 signature. */
  sigQb64: string;
}

/** A transferable receipt (receiptor AID, sn, digest, indexed sig). */
export interface TransReceipt {
  /** Receiptor prefix qb64. */
  receiptorPrefix: string;
  /** Receiptor's sequence number at time of receipt. */
  receiptorSn: number;
  /** Receiptor's event SAID at time of receipt. */
  receiptorSaid: string;
  /** Indexed signature. */
  siger: { index: number; raw: Uint8Array; qb64: string };
}

/** Collection of receipts for an event. */
export interface ReceiptSet {
  nonTrans: NonTransReceipt[];
  trans: TransReceipt[];
}

/**
 * Storage contract for event receipts.
 * Consumers provide their own implementation.
 */
export interface IReceiptStore {
  /** Store non-transferable receipt. */
  putNonTransReceipt(
    prefix: string,
    said: string,
    receipt: NonTransReceipt,
  ): Promise<void>;

  /** Store transferable receipt. */
  putTransReceipt(
    prefix: string,
    said: string,
    receipt: TransReceipt,
  ): Promise<void>;

  /** Get all receipts for an event. */
  getReceipts(prefix: string, said: string): Promise<ReceiptSet>;
}
