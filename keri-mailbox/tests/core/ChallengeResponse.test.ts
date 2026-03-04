import { describe, it, expect } from "vitest";
import { generateNonce, verifyResponse } from "../../src/core/ChallengeResponse.js";
import {
  generateKeyPair,
  signMessage,
  encodeEd25519IndexedSig,
  makeKeyState,
} from "../helpers.js";

describe("generateNonce", () => {
  it("returns a 22-character string", () => {
    const nonce = generateNonce();
    expect(nonce).toHaveLength(22);
  });

  it("returns unique values on each call", () => {
    const n1 = generateNonce();
    const n2 = generateNonce();
    expect(n1).not.toBe(n2);
  });

  it("uses only CESR base64 alphabet characters", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9\-_]{22}$/);
  });
});

describe("verifyResponse", () => {
  it("returns true for a valid signature over the nonce", async () => {
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    const nonce = generateNonce();
    const message = new TextEncoder().encode(nonce);
    const sigBytes = await signMessage(kp.privateKey, message);
    const sigQb64 = encodeEd25519IndexedSig(sigBytes, 0);

    const result = await verifyResponse(nonce, sigQb64, ks);
    expect(result).toBe(true);
  });

  it("returns false for a signature over a different message", async () => {
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    const nonce = generateNonce();
    const wrongMessage = new TextEncoder().encode("wrong");
    const sigBytes = await signMessage(kp.privateKey, wrongMessage);
    const sigQb64 = encodeEd25519IndexedSig(sigBytes, 0);

    const result = await verifyResponse(nonce, sigQb64, ks);
    expect(result).toBe(false);
  });

  it("returns false for a signature from the wrong key", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const ks = makeKeyState(kp1.verferQb64);
    const nonce = generateNonce();
    const message = new TextEncoder().encode(nonce);
    const sigBytes = await signMessage(kp2.privateKey, message);
    const sigQb64 = encodeEd25519IndexedSig(sigBytes, 0);

    const result = await verifyResponse(nonce, sigQb64, ks);
    expect(result).toBe(false);
  });

  it("returns false for an invalid qb64 string", async () => {
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    const nonce = generateNonce();
    const result = await verifyResponse(nonce, "not-valid-qb64!!!", ks);
    expect(result).toBe(false);
  });
});
