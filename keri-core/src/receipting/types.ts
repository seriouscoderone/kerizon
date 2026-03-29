export type ReceiptType = 'NonTransferable' | 'Transferable' | 'WitnessIndexed';

export interface Receipt {
  readonly prefix: string;
  readonly sn: number;
  readonly eventSaid: string;
  readonly signerAid: string;
  readonly receiptType: ReceiptType;
  readonly signature: string;
  readonly index?: number;
}
