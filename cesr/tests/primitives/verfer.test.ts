import { describe, it, expect } from 'vitest';
import { Verfer } from '../../src/primitives/verfer.js';
import { Signer } from '../../src/primitives/signer.js';
import { MtrDex } from '../../src/primitives/code-table.js';

describe('Verfer', () => {
  it('constructs from raw 32-byte public key with code D', () => {
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const v = new Verfer({ code: MtrDex.Ed25519, raw });
    expect(v.code).toBe('D');
    expect(v.raw).toEqual(raw);
    expect(v.qb64).toHaveLength(44);
    expect(v.qb64[0]).toBe('D');
  });

  it('constructs from raw 32-byte public key with code B (non-transferable)', () => {
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const v = new Verfer({ code: MtrDex.Ed25519N, raw });
    expect(v.code).toBe('B');
    expect(v.raw).toEqual(raw);
    expect(v.qb64).toHaveLength(44);
    expect(v.qb64[0]).toBe('B');
  });

  it('constructs from qb64', () => {
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const v1 = new Verfer({ code: MtrDex.Ed25519, raw });
    const v2 = new Verfer({ qb64: v1.qb64 });
    expect(v2.code).toBe('D');
    expect(v2.raw).toEqual(raw);
  });

  it('verifies a valid Ed25519 signature', async () => {
    const signer = await Signer.generate();
    const verfer = signer.verfer;
    const message = new TextEncoder().encode('Hello, KERI!');
    const sig = await signer.sign(message);

    const valid = await verfer.verify(sig, message);
    expect(valid).toBe(true);
  });

  it('rejects a signature when data is tampered', async () => {
    const signer = await Signer.generate();
    const verfer = signer.verfer;
    const message = new TextEncoder().encode('Hello, KERI!');
    const sig = await signer.sign(message);

    const tampered = new TextEncoder().encode('Hello, KERI?');
    const valid = await verfer.verify(sig, tampered);
    expect(valid).toBe(false);
  });

  it('rejects a signature when sig bytes are tampered', async () => {
    const signer = await Signer.generate();
    const verfer = signer.verfer;
    const message = new TextEncoder().encode('test data');
    const sig = await signer.sign(message);

    const badSig = new Uint8Array(sig);
    badSig[0] ^= 0xff;
    const valid = await verfer.verify(badSig, message);
    expect(valid).toBe(false);
  });

  it('verifies with code B (Ed25519N) the same as code D', async () => {
    // Signer generates with code A (seed), verfer defaults to D.
    // We can re-wrap the same public key as B and verify still works.
    const signer = await Signer.generate();
    const pubRaw = signer.verfer.raw;
    const verferN = new Verfer({ code: MtrDex.Ed25519N, raw: pubRaw });

    const message = new TextEncoder().encode('non-transferable test');
    const sig = await signer.sign(message);

    const valid = await verferN.verify(sig, message);
    expect(valid).toBe(true);
  });

  it('throws for unsupported code', async () => {
    const raw = new Uint8Array(32);
    const v = new Verfer({ code: MtrDex.X25519, raw });
    expect(v.code).toBe('C');
    await expect(v.verify(new Uint8Array(64), new Uint8Array(10))).rejects.toThrow();
  });
});
