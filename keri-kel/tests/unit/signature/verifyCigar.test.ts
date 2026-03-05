import { describe, it, expect } from "vitest";
import { verifyCigar, verifyCigars } from "../../../src/core/signature/verifyCigar.js";
import { generateKeyPair, signMessage } from "../../helpers.js";
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

describe("verifyCigar", () => {
  it("verifies a valid unindexed signature", async () => {
    const kp = await generateKeyPair();
    const message = new TextEncoder().encode("receipt target");
    const sigBytes = await signMessage(kp.privateKey, message);

    const result = await verifyCigar(testCrypto, message, {
      verferQb64: kp.verferQb64,
      sigRaw: sigBytes,
    });

    expect(result).toBe(true);
  });

  it("rejects an invalid unindexed signature", async () => {
    const kp = await generateKeyPair();
    const message = new TextEncoder().encode("receipt target");
    const badSig = new Uint8Array(64);

    const result = await verifyCigar(testCrypto, message, {
      verferQb64: kp.verferQb64,
      sigRaw: badSig,
    });

    expect(result).toBe(false);
  });
});

describe("verifyCigars", () => {
  it("returns verified verfer qb64 strings", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("batch receipt");
    const sig1 = await signMessage(kp1.privateKey, message);
    const sig2 = await signMessage(kp2.privateKey, message);

    const result = await verifyCigars(testCrypto, message, [
      { verferQb64: kp1.verferQb64, sigRaw: sig1 },
      { verferQb64: kp2.verferQb64, sigRaw: sig2 },
    ]);

    expect(result).toEqual([kp1.verferQb64, kp2.verferQb64]);
  });

  it("filters out invalid signatures", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("batch receipt");
    const sig1 = await signMessage(kp1.privateKey, message);
    const badSig = new Uint8Array(64);

    const result = await verifyCigars(testCrypto, message, [
      { verferQb64: kp1.verferQb64, sigRaw: sig1 },
      { verferQb64: kp2.verferQb64, sigRaw: badSig },
    ]);

    expect(result).toEqual([kp1.verferQb64]);
  });
});
