import { describe, it, expect } from "vitest";
import {
  verifySigs,
  satisfyThreshold,
  validateSigs,
  verifyWitnessSigs,
} from "../../../src/verification.js";
import type { CryptoProvider, IndexedSiger, CigarSig } from "../../../src/verification.js";
import {
  generateKeyPair,
  signMessage,
  encodeEd25519IndexedSig,
} from "../../helpers.js";

// ── Real CryptoProvider using Web Crypto ─────────────────────────────

const crypto: CryptoProvider = {
  async verifySignature(pubKey, sig, msg) {
    try {
      const key = await globalThis.crypto.subtle.importKey(
        "raw",
        pubKey.slice(),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return await globalThis.crypto.subtle.verify(
        "Ed25519",
        key,
        sig.slice(),
        msg.slice(),
      );
    } catch {
      return false;
    }
  },
  async digest(data) {
    return new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", data.slice()),
    );
  },
};

// ── Helper ──────────────────────────────────────────────────────────

function makeSiger(
  sigBytes: Uint8Array,
  index: number,
  ondex?: number,
): IndexedSiger {
  return {
    index,
    ondex,
    raw: sigBytes,
    qb64: encodeEd25519IndexedSig(sigBytes, index),
  };
}

// ── Authorization pipeline tests ─────────────────────────────────────

describe("Authorization — controller sigs meet threshold (full pipeline)", () => {
  it("A01: 2-of-3 threshold — all 3 sign, threshold satisfied", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("authorized event");

    const sig0 = await signMessage(kp0.privateKey, message);
    const sig1 = await signMessage(kp1.privateKey, message);
    const sig2 = await signMessage(kp2.privateKey, message);

    const sigers: IndexedSiger[] = [
      makeSiger(sig0, 0),
      makeSiger(sig1, 1),
      makeSiger(sig2, 2),
    ];

    const result = await validateSigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
      "2",
    );

    expect(result.satisfied).toBe(true);
    expect(result.verifiedIndices).toEqual([0, 1, 2]);
  });

  it("A02: 2-of-3 threshold — only 1 signs, threshold not satisfied", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("under-signed event");

    const sig0 = await signMessage(kp0.privateKey, message);

    const sigers: IndexedSiger[] = [makeSiger(sig0, 0)];

    const result = await validateSigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
      "2",
    );

    expect(result.satisfied).toBe(false);
    expect(result.verifiedIndices).toEqual([0]);
  });

  it("A03: witness sigs — indexed witnesses verified via verifyWitnessSigs", async () => {
    const kpWit0 = await generateKeyPair();
    const kpWit1 = await generateKeyPair();
    const kpWit2 = await generateKeyPair();
    const message = new TextEncoder().encode("witnessed event");

    const witSig0 = await signMessage(kpWit0.privateKey, message);
    const witSig1 = await signMessage(kpWit1.privateKey, message);

    const wigers: IndexedSiger[] = [
      makeSiger(witSig0, 0),
      makeSiger(witSig1, 1),
    ];

    const witnessList = [
      kpWit0.verferQb64,
      kpWit1.verferQb64,
      kpWit2.verferQb64,
    ];

    const result = await verifyWitnessSigs(
      crypto,
      message,
      witnessList,
      wigers,
    );

    expect(result.verifiedWitnessIndices).toEqual([0, 1]);
    expect(result.count).toBe(2);
  });

  it("A04: witness sigs — unindexed cigars verified via verifyWitnessSigs", async () => {
    const kpWit0 = await generateKeyPair();
    const kpWit1 = await generateKeyPair();
    const message = new TextEncoder().encode("cigar witnessed event");

    const cigarSig0 = await signMessage(kpWit0.privateKey, message);
    const cigarSig1 = await signMessage(kpWit1.privateKey, message);

    const cigars: CigarSig[] = [
      { verferQb64: kpWit0.verferQb64, sigRaw: cigarSig0 },
      { verferQb64: kpWit1.verferQb64, sigRaw: cigarSig1 },
    ];

    const witnessList = [kpWit0.verferQb64, kpWit1.verferQb64];

    const result = await verifyWitnessSigs(
      crypto,
      message,
      witnessList,
      [],
      cigars,
    );

    expect(result.verifiedWitnessIndices).toEqual([0, 1]);
    expect(result.count).toBe(2);
  });

  it("A05: witness cigar for non-witness prefix is excluded", async () => {
    const kpWit0 = await generateKeyPair();
    const kpRandom = await generateKeyPair();
    const message = new TextEncoder().encode("non-witness cigar");

    const cigarSig = await signMessage(kpRandom.privateKey, message);

    const cigars: CigarSig[] = [
      { verferQb64: kpRandom.verferQb64, sigRaw: cigarSig },
    ];

    const witnessList = [kpWit0.verferQb64];

    const result = await verifyWitnessSigs(
      crypto,
      message,
      witnessList,
      [],
      cigars,
    );

    expect(result.verifiedWitnessIndices).toEqual([]);
    expect(result.count).toBe(0);
  });

  it("A06: mixed wigers and cigars — deduplication by witness index", async () => {
    const kpWit0 = await generateKeyPair();
    const kpWit1 = await generateKeyPair();
    const message = new TextEncoder().encode("mixed witness sigs");

    // Witness 0 via indexed siger
    const wigerSig0 = await signMessage(kpWit0.privateKey, message);
    const wigers: IndexedSiger[] = [makeSiger(wigerSig0, 0)];

    // Witness 0 also via cigar + witness 1 via cigar
    const cigarSig0 = await signMessage(kpWit0.privateKey, message);
    const cigarSig1 = await signMessage(kpWit1.privateKey, message);
    const cigars: CigarSig[] = [
      { verferQb64: kpWit0.verferQb64, sigRaw: cigarSig0 },
      { verferQb64: kpWit1.verferQb64, sigRaw: cigarSig1 },
    ];

    const witnessList = [kpWit0.verferQb64, kpWit1.verferQb64];

    const result = await verifyWitnessSigs(
      crypto,
      message,
      witnessList,
      wigers,
      cigars,
    );

    // Both witness 0 and 1 verified, deduped to unique indices
    expect(result.verifiedWitnessIndices).toEqual([0, 1]);
    expect(result.count).toBe(2);
  });

  it("A07: weighted threshold authorization — full pipeline", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const message = new TextEncoder().encode("weighted auth");

    const sig0 = await signMessage(kp0.privateKey, message);
    const sig1 = await signMessage(kp1.privateKey, message);

    const sigers: IndexedSiger[] = [
      makeSiger(sig0, 0),
      makeSiger(sig1, 1),
    ];

    // Weighted threshold: each key has weight 1/2 — need both
    const result = await validateSigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64],
      [["1/2", "1/2"]],
    );

    expect(result.satisfied).toBe(true);

    // With only one sig, should not satisfy
    const result2 = await validateSigs(
      crypto,
      message,
      [makeSiger(sig0, 0)],
      [kp0.verferQb64, kp1.verferQb64],
      [["1/2", "1/2"]],
    );

    expect(result2.satisfied).toBe(false);
  });

  it("A08: 1-of-1 threshold — single controller authorized", async () => {
    const kp = await generateKeyPair();
    const message = new TextEncoder().encode("single key auth");

    const sig = await signMessage(kp.privateKey, message);
    const sigers: IndexedSiger[] = [makeSiger(sig, 0)];

    const result = await validateSigs(
      crypto,
      message,
      sigers,
      [kp.verferQb64],
      "1",
    );

    expect(result.satisfied).toBe(true);
    expect(result.verifiedIndices).toEqual([0]);
  });

  it("A09: 3-of-3 threshold — 2 valid sigs not enough", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("strict threshold");

    const sig0 = await signMessage(kp0.privateKey, message);
    const sig1 = await signMessage(kp1.privateKey, message);

    const sigers: IndexedSiger[] = [
      makeSiger(sig0, 0),
      makeSiger(sig1, 1),
    ];

    const result = await validateSigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
      "3",
    );

    expect(result.satisfied).toBe(false);
    expect(result.verifiedIndices).toEqual([0, 1]);
  });

  it("A10: invalid sig among valid ones — only valid ones count", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("mixed validity");

    const sig0 = await signMessage(kp0.privateKey, message);
    const garbage = new Uint8Array(64);
    globalThis.crypto.getRandomValues(garbage);
    const sig2 = await signMessage(kp2.privateKey, message);

    const sigers: IndexedSiger[] = [
      makeSiger(sig0, 0),
      makeSiger(garbage, 1),
      makeSiger(sig2, 2),
    ];

    const result = await validateSigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
      "2",
    );

    expect(result.satisfied).toBe(true);
    expect(result.verifiedIndices).toEqual([0, 2]);
  });

  it("A11: empty witness list — verifyWitnessSigs returns empty", async () => {
    const message = new TextEncoder().encode("no witnesses");

    const result = await verifyWitnessSigs(
      crypto,
      message,
      [],
      [],
      [],
    );

    expect(result.verifiedWitnessIndices).toEqual([]);
    expect(result.count).toBe(0);
  });

  it("A12: verify + threshold with tampered message fails", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const originalMsg = new TextEncoder().encode("original message");
    const tamperedMsg = new TextEncoder().encode("tampered message");

    const sig0 = await signMessage(kp0.privateKey, originalMsg);
    const sig1 = await signMessage(kp1.privateKey, originalMsg);

    const sigers: IndexedSiger[] = [
      makeSiger(sig0, 0),
      makeSiger(sig1, 1),
    ];

    // Sigs were for original, verify against tampered
    const result = await validateSigs(
      crypto,
      tamperedMsg,
      sigers,
      [kp0.verferQb64, kp1.verferQb64],
      "1",
    );

    expect(result.satisfied).toBe(false);
    expect(result.verifiedIndices).toEqual([]);
  });
});
