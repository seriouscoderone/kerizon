import { describe, it, expect } from 'vitest';
import { Signer } from '@kerizon/cesr';
import { createReceipt, classifyReceipt } from '../../src/receipting/create.js';

describe('createReceipt', () => {
  it('produces receipt with correct fields', async () => {
    const signer = await Signer.generate();
    const receipt = await createReceipt({
      prefix: 'EAbcdefghijklmnopqrstuvwxyz012345678901234567',
      sn: 0,
      eventSaid: 'EAbcdefghijklmnopqrstuvwxyz012345678901234567',
      signer,
      signerAid: signer.verfer.qb64,
      index: 0,
    });

    expect(receipt.prefix).toBe('EAbcdefghijklmnopqrstuvwxyz012345678901234567');
    expect(receipt.sn).toBe(0);
    expect(receipt.eventSaid).toBe('EAbcdefghijklmnopqrstuvwxyz012345678901234567');
    expect(receipt.signerAid).toBe(signer.verfer.qb64);
    expect(receipt.index).toBe(0);
    expect(receipt.receiptType).toBe('Transferable');
    expect(receipt.signature).toBeDefined();
  });

  it('signature is 88 chars (Ed25519 indexed)', async () => {
    const signer = await Signer.generate();
    const receipt = await createReceipt({
      prefix: 'EAbcdefghijklmnopqrstuvwxyz012345678901234567',
      sn: 0,
      eventSaid: 'EAbcdefghijklmnopqrstuvwxyz012345678901234567',
      signer,
      signerAid: signer.verfer.qb64,
      index: 0,
    });

    expect(receipt.signature).toHaveLength(88);
  });
});

describe('classifyReceipt', () => {
  it('B-prefix witness is NonTransferable', () => {
    expect(classifyReceipt('BAid', 'witness')).toBe('NonTransferable');
  });

  it('D-prefix witness is Transferable', () => {
    expect(classifyReceipt('DAid', 'witness')).toBe('Transferable');
  });
});
