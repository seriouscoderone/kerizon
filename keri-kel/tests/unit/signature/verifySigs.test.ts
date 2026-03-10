import { describe, it, expect } from "vitest";
import { verifySigs, publicKeyBytesFromQb64 } from "../../../src/core/signature/verifySigs.js";
import {
  generateKeyPair,
  signMessage,
  encodeEd25519IndexedSig,
} from "../../helpers.js";
import type { ICryptoProvider } from "../../../src/interfaces/ICryptoProvider.js";

/** Minimal Ed25519 crypto provider for testing. */
const testCrypto: ICryptoProvider = {
  async verifySignature(publicKeyBytes, signatureBytes, message) {
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes.slice(),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        "Ed25519",
        key,
        signatureBytes.slice(),
        message.slice(),
      );
    } catch {
      return false;
    }
  },
  async digest(data, _algorithm) {
    const hash = await crypto.subtle.digest("SHA-256", data.slice());
    return new Uint8Array(hash);
  },
};

describe("verifySigs", () => {
  it("verifies a single valid signature", async () => {
    const kp = await generateKeyPair();
    const message = new TextEncoder().encode("hello");
    const sigBytes = await signMessage(kp.privateKey, message);
    const qb64 = encodeEd25519IndexedSig(sigBytes, 0);

    const result = await verifySigs(
      testCrypto,
      message,
      [{ index: 0, raw: sigBytes, qb64 }],
      [kp.verferQb64],
    );

    expect(result.verifiedIndices).toEqual([0]);
    expect(result.verifiedSigers).toHaveLength(1);
  });

  it("rejects an invalid signature", async () => {
    const kp = await generateKeyPair();
    const message = new TextEncoder().encode("hello");
    const badSig = new Uint8Array(64); // all zeros
    const qb64 = encodeEd25519IndexedSig(badSig, 0);

    const result = await verifySigs(
      testCrypto,
      message,
      [{ index: 0, raw: badSig, qb64 }],
      [kp.verferQb64],
    );

    expect(result.verifiedIndices).toEqual([]);
    expect(result.verifiedSigers).toHaveLength(0);
  });

  it("skips sigers with out-of-range index", async () => {
    const kp = await generateKeyPair();
    const message = new TextEncoder().encode("hello");
    const sigBytes = await signMessage(kp.privateKey, message);
    const qb64 = encodeEd25519IndexedSig(sigBytes, 5);

    const result = await verifySigs(
      testCrypto,
      message,
      [{ index: 5, raw: sigBytes, qb64 }],
      [kp.verferQb64], // only 1 key, index 5 is out of range
    );

    expect(result.verifiedIndices).toEqual([]);
  });

  it("deduplicates sigers by qb64", async () => {
    const kp = await generateKeyPair();
    const message = new TextEncoder().encode("hello");
    const sigBytes = await signMessage(kp.privateKey, message);
    const qb64 = encodeEd25519IndexedSig(sigBytes, 0);

    const result = await verifySigs(
      testCrypto,
      message,
      [
        { index: 0, raw: sigBytes, qb64 },
        { index: 0, raw: sigBytes, qb64 }, // duplicate
      ],
      [kp.verferQb64],
    );

    expect(result.verifiedIndices).toEqual([0]);
    expect(result.verifiedSigers).toHaveLength(1);
  });

  it("deduplicates by index (first valid per index wins)", async () => {
    const kp = await generateKeyPair();
    const message = new TextEncoder().encode("hello");
    const sigBytes1 = await signMessage(kp.privateKey, message);
    const sigBytes2 = await signMessage(kp.privateKey, message);
    const qb641 = encodeEd25519IndexedSig(sigBytes1, 0);
    const qb642 = encodeEd25519IndexedSig(sigBytes2, 0);

    const result = await verifySigs(
      testCrypto,
      message,
      [
        { index: 0, raw: sigBytes1, qb64: qb641 },
        { index: 0, raw: sigBytes2, qb64: qb642 },
      ],
      [kp.verferQb64],
    );

    expect(result.verifiedIndices).toEqual([0]);
    expect(result.verifiedSigers).toHaveLength(1);
    expect(result.verifiedSigers[0].qb64).toBe(qb641);
  });

  it("verifies multiple keys in a multi-sig setup", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("multi-sig message");
    const sig1 = await signMessage(kp1.privateKey, message);
    const sig2 = await signMessage(kp2.privateKey, message);

    const result = await verifySigs(
      testCrypto,
      message,
      [
        { index: 0, raw: sig1, qb64: encodeEd25519IndexedSig(sig1, 0) },
        { index: 1, raw: sig2, qb64: encodeEd25519IndexedSig(sig2, 1) },
      ],
      [kp1.verferQb64, kp2.verferQb64],
    );

    expect(result.verifiedIndices).toEqual([0, 1]);
    expect(result.verifiedSigers).toHaveLength(2);
  });
});

describe("publicKeyBytesFromQb64", () => {
  it("round-trips an Ed25519 public key", async () => {
    const kp = await generateKeyPair();
    const parsed = publicKeyBytesFromQb64(kp.verferQb64);
    expect(parsed.length).toBe(32);
    expect(new Uint8Array(parsed)).toEqual(kp.publicKeyBytes);
  });
});
