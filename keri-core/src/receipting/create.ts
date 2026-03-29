/**
 * Receipt creation — signs an event SAID with a witness signer
 * and produces a Receipt with an indexed signature (Siger).
 */

import { Signer, Siger } from '@kerizon/cesr';
import type { Receipt, ReceiptType } from './types.js';

/** Non-transferable prefix codes (Ed25519N, ECDSA_256k1N, Ed448N, ECDSA_256r1N). */
const NON_TRANSFERABLE_CODES = new Set(['B', '1AAA', '1AAC', '1AAI']);

export interface CreateReceiptOpts {
  /** Identifier prefix of the event being receipted. */
  prefix: string;
  /** Sequence number of the event being receipted. */
  sn: number;
  /** SAID (Self-Addressing Identifier) of the event being receipted. */
  eventSaid: string;
  /** Signer (private key) of the witness producing this receipt. */
  signer: Signer;
  /** AID (qb64 prefix) of the signing witness. */
  signerAid: string;
  /** Signing key index within the witness set. */
  index: number;
}

/**
 * Create a receipt by signing the eventSaid with the witness signer.
 *
 * The eventSaid string is encoded to UTF-8 bytes, signed, and the resulting
 * Ed25519 signature is wrapped into a Siger (indexed signature primitive).
 */
export async function createReceipt(opts: CreateReceiptOpts): Promise<Receipt> {
  const { prefix, sn, eventSaid, signer, signerAid, index } = opts;

  const ser = new TextEncoder().encode(eventSaid);
  const sigRaw = await signer.sign(ser);
  const siger = Siger.create({ raw: sigRaw, index });

  const receiptType = classifyReceipt(signerAid, 'witness');

  return {
    prefix,
    sn,
    eventSaid,
    signerAid,
    receiptType,
    signature: siger.qb64,
    index,
  };
}

/**
 * Classify a receipt based on the signer AID prefix code.
 *
 * AIDs starting with non-transferable prefix codes (B, 1AAA, 1AAC, 1AAI)
 * produce NonTransferable receipts; all others produce Transferable receipts.
 */
export function classifyReceipt(signerAid: string, _role: string): ReceiptType {
  // Extract the code: check for 4-char codes first, then 1-char
  const fourChar = signerAid.substring(0, 4);
  if (NON_TRANSFERABLE_CODES.has(fourChar)) {
    return 'NonTransferable';
  }
  const oneChar = signerAid[0];
  if (NON_TRANSFERABLE_CODES.has(oneChar)) {
    return 'NonTransferable';
  }
  return 'Transferable';
}
