import { describe, it, expect } from 'vitest';
import { KERL } from '../../src/accountability/kerl.js';
import type { ReceiptRef } from '../../src/accountability/kerl.js';

describe('KERL', () => {
  it('starts empty', () => {
    const kerl = new KERL('EPrefix123');
    expect(kerl.getReceiptedEvent(0)).toBeUndefined();
  });

  it('append event and retrieve by sn', () => {
    const kerl = new KERL('EPrefix123');
    kerl.appendEvent('ESaid000', 0, []);
    const ev = kerl.getReceiptedEvent(0);
    expect(ev).toBeDefined();
    expect(ev!.said).toBe('ESaid000');
    expect(ev!.sn).toBe(0);
    expect(ev!.receipts).toHaveLength(0);
  });

  it('add receipt to existing event', () => {
    const kerl = new KERL('EPrefix123');
    kerl.appendEvent('ESaid000', 0, []);
    const receipt: ReceiptRef = { signerAid: 'BWitness1', signature: 'AABBCCsig' };
    kerl.addReceipt('ESaid000', receipt);
    const receipts = kerl.getReceipts('ESaid000');
    expect(receipts).toHaveLength(1);
    expect(receipts[0].signerAid).toBe('BWitness1');
  });

  it('getReceiptedEvent returns undefined for missing sn', () => {
    const kerl = new KERL('EPrefix123');
    kerl.appendEvent('ESaid000', 0, []);
    expect(kerl.getReceiptedEvent(5)).toBeUndefined();
  });
});
