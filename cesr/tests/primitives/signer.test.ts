import { describe, it, expect } from 'vitest';
import { Signer } from '../../src/primitives/signer.js';
import { Verfer } from '../../src/primitives/verfer.js';
import { MtrDex } from '../../src/primitives/code-table.js';

describe('Signer', () => {
  describe('static generate()', () => {
    it('generates a Signer with code A (Ed25519_Seed)', async () => {
      const signer = await Signer.generate();
      expect(signer.code).toBe('A');
      expect(signer.raw).toHaveLength(32);
      expect(signer.qb64).toHaveLength(44);
      expect(signer.qb64[0]).toBe('A');
    });

    it('generates unique keys each time', async () => {
      const s1 = await Signer.generate();
      const s2 = await Signer.generate();
      expect(s1.raw).not.toEqual(s2.raw);
      expect(s1.qb64).not.toBe(s2.qb64);
    });
  });

  describe('verfer', () => {
    it('returns a Verfer with code D (Ed25519)', async () => {
      const signer = await Signer.generate();
      const verfer = signer.verfer;
      expect(verfer).toBeInstanceOf(Verfer);
      expect(verfer.code).toBe('D');
      expect(verfer.raw).toHaveLength(32);
    });

    it('is lazily computed but stable', async () => {
      const signer = await Signer.generate();
      const v1 = signer.verfer;
      const v2 = signer.verfer;
      expect(v1).toBe(v2); // same instance
    });
  });

  describe('sign()', () => {
    it('produces a 64-byte Ed25519 signature', async () => {
      const signer = await Signer.generate();
      const message = new TextEncoder().encode('Sign me');
      const sig = await signer.sign(message);
      expect(sig).toBeInstanceOf(Uint8Array);
      expect(sig).toHaveLength(64);
    });

    it('produces deterministic signatures for same key+message', async () => {
      const signer = await Signer.generate();
      const message = new TextEncoder().encode('deterministic');
      const sig1 = await signer.sign(message);
      const sig2 = await signer.sign(message);
      expect(sig1).toEqual(sig2);
    });

    it('produces different signatures for different messages', async () => {
      const signer = await Signer.generate();
      const sig1 = await signer.sign(new TextEncoder().encode('message A'));
      const sig2 = await signer.sign(new TextEncoder().encode('message B'));
      expect(sig1).not.toEqual(sig2);
    });
  });

  describe('Signer-Verfer binding', () => {
    it('sign then verify round-trip succeeds', async () => {
      const signer = await Signer.generate();
      const message = new TextEncoder().encode('round trip');
      const sig = await signer.sign(message);
      const valid = await signer.verfer.verify(sig, message);
      expect(valid).toBe(true);
    });

    it('verify fails with wrong verfer', async () => {
      const signer1 = await Signer.generate();
      const signer2 = await Signer.generate();
      const message = new TextEncoder().encode('cross check');
      const sig = await signer1.sign(message);
      const valid = await signer2.verfer.verify(sig, message);
      expect(valid).toBe(false);
    });
  });

  describe('construct from raw seed', () => {
    it('accepts a known 32-byte seed and derives the correct verfer', async () => {
      const signer1 = await Signer.generate();
      const seed = signer1.raw;

      // Reconstruct from the same seed
      const signer2 = new Signer({ code: MtrDex.Ed25519_Seed, raw: seed });
      expect(signer2.verfer.qb64).toBe(signer1.verfer.qb64);

      // Sign with reconstructed signer and verify with original verfer
      const msg = new TextEncoder().encode('reconstruct test');
      const sig = await signer2.sign(msg);
      const valid = await signer1.verfer.verify(sig, msg);
      expect(valid).toBe(true);
    });
  });
});
