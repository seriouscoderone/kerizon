import { describe, it, expect } from "vitest";
import { verifyWitnessSigs } from "../../../src/core/witness/verifyWitnessSigs.js";
import {
  generateKeyPair,
  signMessage,
  encodeEd25519IndexedSig,
} from "../../helpers.js";
import type { ICryptoProvider } from "../../../src/interfaces/ICryptoProvider.js";

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
  async digest(data) {
    const hash = await crypto.subtle.digest("SHA-256", data.slice());
    return new Uint8Array(hash);
  },
};

describe("verifyWitnessSigs", () => {
  it("verifies indexed witness signatures", async () => {
    const w1 = await generateKeyPair();
    const w2 = await generateKeyPair();
    const message = new TextEncoder().encode("event body");
    const sig1 = await signMessage(w1.privateKey, message);
    const sig2 = await signMessage(w2.privateKey, message);

    const result = await verifyWitnessSigs(
      testCrypto,
      message,
      [w1.verferQb64, w2.verferQb64],
      [
        { index: 0, raw: sig1, qb64: encodeEd25519IndexedSig(sig1, 0) },
        { index: 1, raw: sig2, qb64: encodeEd25519IndexedSig(sig2, 1) },
      ],
    );

    expect(result.count).toBe(2);
    expect(result.verifiedWitnessIndices).toEqual([0, 1]);
  });

  it("verifies unindexed (cigar) witness receipts", async () => {
    const w1 = await generateKeyPair();
    const message = new TextEncoder().encode("event body");
    const sig = await signMessage(w1.privateKey, message);

    const result = await verifyWitnessSigs(
      testCrypto,
      message,
      [w1.verferQb64],
      [],
      [{ verferQb64: w1.verferQb64, sigRaw: sig }],
    );

    expect(result.count).toBe(1);
    expect(result.verifiedWitnessIndices).toEqual([0]);
  });

  it("deduplicates across indexed and unindexed", async () => {
    const w1 = await generateKeyPair();
    const message = new TextEncoder().encode("event body");
    const sig1 = await signMessage(w1.privateKey, message);
    const sig2 = await signMessage(w1.privateKey, message);

    const result = await verifyWitnessSigs(
      testCrypto,
      message,
      [w1.verferQb64],
      [{ index: 0, raw: sig1, qb64: encodeEd25519IndexedSig(sig1, 0) }],
      [{ verferQb64: w1.verferQb64, sigRaw: sig2 }],
    );

    expect(result.count).toBe(1);
  });

  it("ignores cigar for unknown witness", async () => {
    const w1 = await generateKeyPair();
    const unknown = await generateKeyPair();
    const message = new TextEncoder().encode("event body");
    const sig = await signMessage(unknown.privateKey, message);

    const result = await verifyWitnessSigs(
      testCrypto,
      message,
      [w1.verferQb64],
      [],
      [{ verferQb64: unknown.verferQb64, sigRaw: sig }],
    );

    expect(result.count).toBe(0);
  });
});
