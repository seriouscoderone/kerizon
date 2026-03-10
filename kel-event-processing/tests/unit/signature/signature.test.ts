import { describe, it, expect } from "vitest";
import {
  verifySigs,
  satisfyThreshold,
  validateSigs,
  ampleSufficient,
  verifyWitnessSigs,
} from "../../../src/verification.js";
import type { CryptoProvider, IndexedSiger } from "../../../src/verification.js";
import {
  generateKeyPair,
  signMessage,
  encodeEd25519Verfer,
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

// ── Helper to build an IndexedSiger from sig bytes + index ──────────

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

// ── verifySigs tests ─────────────────────────────────────────────────

describe("verifySigs", () => {
  it("S01: all 3 valid sigs returns all indices", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("hello KERI");

    const sig0 = await signMessage(kp0.privateKey, message);
    const sig1 = await signMessage(kp1.privateKey, message);
    const sig2 = await signMessage(kp2.privateKey, message);

    const sigers: IndexedSiger[] = [
      makeSiger(sig0, 0),
      makeSiger(sig1, 1),
      makeSiger(sig2, 2),
    ];

    const result = await verifySigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
    );

    expect(result.verifiedIndices).toEqual([0, 1, 2]);
    expect(result.verifiedSigers).toHaveLength(3);
  });

  it("S02: partial valid sigs — only key0 and key2 verified", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("partial verification");

    const sig0 = await signMessage(kp0.privateKey, message);
    // key1 signs with wrong key (use kp0's private key to produce wrong sig for kp1)
    const wrongSig1 = await signMessage(kp0.privateKey, message);
    const sig2 = await signMessage(kp2.privateKey, message);

    const sigers: IndexedSiger[] = [
      makeSiger(sig0, 0),
      makeSiger(wrongSig1, 1),
      makeSiger(sig2, 2),
    ];

    const result = await verifySigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
    );

    expect(result.verifiedIndices).toEqual([0, 2]);
    expect(result.verifiedSigers).toHaveLength(2);
  });

  it("S03: all garbage sigs returns empty", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const message = new TextEncoder().encode("garbage test");

    const garbage = new Uint8Array(64);
    globalThis.crypto.getRandomValues(garbage);

    const sigers: IndexedSiger[] = [
      makeSiger(new Uint8Array(garbage), 0),
      makeSiger(new Uint8Array(garbage), 1),
      makeSiger(new Uint8Array(garbage), 2),
    ];

    const result = await verifySigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
    );

    expect(result.verifiedIndices).toEqual([]);
    expect(result.verifiedSigers).toHaveLength(0);
  });

  it("S04: duplicate sigs for same index — first valid one kept", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const message = new TextEncoder().encode("dedup test");

    const sig0 = await signMessage(kp0.privateKey, message);
    // Second sig for index 0 with different key — different qb64
    const wrongSig0 = await signMessage(kp1.privateKey, message);

    const sigers: IndexedSiger[] = [
      makeSiger(sig0, 0),
      // Second siger with same index=0 but different qb64
      {
        index: 0,
        raw: wrongSig0,
        qb64: encodeEd25519IndexedSig(wrongSig0, 0),
      },
    ];

    const result = await verifySigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64],
    );

    // First valid sig at index 0 wins, second is skipped (indexMap.has check)
    expect(result.verifiedIndices).toEqual([0]);
    expect(result.verifiedSigers).toHaveLength(1);
    expect(result.verifiedSigers[0].raw).toBe(sig0);
  });
});

// ── satisfyThreshold tests ───────────────────────────────────────────

describe("satisfyThreshold", () => {
  it("S05: simple threshold '2' with indices [0,1] satisfied", () => {
    expect(satisfyThreshold("2", [0, 1])).toBe(true);
  });

  it("S06: simple threshold '2' with indices [0] not satisfied", () => {
    expect(satisfyThreshold("2", [0])).toBe(false);
  });

  it("S07: weighted threshold [['1/2','1/2']] with [0,1] satisfied (0.5+0.5>=1)", () => {
    expect(satisfyThreshold([["1/2", "1/2"]], [0, 1])).toBe(true);
  });

  it("S08: weighted threshold [['1/2','1/2']] with [0] not satisfied (0.5<1)", () => {
    expect(satisfyThreshold([["1/2", "1/2"]], [0])).toBe(false);
  });

  it("S09: multi-clause weighted threshold — both clauses must be satisfied", () => {
    // Clause 0: ["1/2","1/2"] — needs indices 0,1 or both for sum>=1
    // Clause 1: ["1"] — needs index 2 for sum>=1
    // Flat map: idx0 -> (0,0), idx1 -> (0,1), idx2 -> (1,0)
    const threshold: string[][] = [["1/2", "1/2"], ["1"]];

    // All three indices — both clauses satisfied
    expect(satisfyThreshold(threshold, [0, 1, 2])).toBe(true);

    // Only indices 0,1 — clause 0 satisfied but clause 1 not
    expect(satisfyThreshold(threshold, [0, 1])).toBe(false);

    // Only index 2 — clause 1 satisfied but clause 0 not
    expect(satisfyThreshold(threshold, [2])).toBe(false);
  });

  it("S10: weighted threshold with mixed fractions", () => {
    // Clause 0: ["1/3","1/3","1/3"] — need all 3 to sum >= 1
    const threshold: string[][] = [["1/3", "1/3", "1/3"]];

    expect(satisfyThreshold(threshold, [0, 1, 2])).toBe(true);
    expect(satisfyThreshold(threshold, [0, 1])).toBe(false);
  });
});

// ── ampleSufficient tests ────────────────────────────────────────────

describe("ampleSufficient", () => {
  it("S11: default f computation — n=3 yields 2, n=4 yields 3, n=6 yields 4", () => {
    // n=3: f=floor(2/3)=0, m=ceil((3+0+1)/2)=ceil(2)=2
    expect(ampleSufficient(3)).toBe(2);

    // n=4: f=floor(3/3)=1, m=ceil((4+1+1)/2)=ceil(3)=3
    expect(ampleSufficient(4)).toBe(3);

    // n=6: f=floor(5/3)=1, m=ceil((6+1+1)/2)=ceil(4)=4
    expect(ampleSufficient(6)).toBe(4);
  });

  it("S12: explicit f — ampleSufficient(7, 2) = 5", () => {
    // f=2, m=ceil((7+2+1)/2)=ceil(5)=5
    expect(ampleSufficient(7, 2)).toBe(5);
  });

  it("S13: edge cases — n=0 yields 0, n=1 yields 1", () => {
    expect(ampleSufficient(0)).toBe(0);

    // n=1: f=floor(0/3)=0, m=ceil((1+0+1)/2)=ceil(1)=1
    // weak=true → max(1,1)=1
    expect(ampleSufficient(1)).toBe(1);
    expect(ampleSufficient(1, undefined, true)).toBe(1);
    expect(ampleSufficient(1, undefined, false)).toBe(1);

    // n=4 weak vs strong: both should be 3
    expect(ampleSufficient(4, undefined, true)).toBe(3);
    expect(ampleSufficient(4, undefined, false)).toBe(3);
  });
});

// ── validateSigs (combined verifySigs + satisfyThreshold) ────────────

describe("validateSigs", () => {
  it("combines verification and threshold check", async () => {
    const kp0 = await generateKeyPair();
    const kp1 = await generateKeyPair();
    const message = new TextEncoder().encode("validate combined");

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
      [kp0.verferQb64, kp1.verferQb64],
      "2",
    );

    expect(result.satisfied).toBe(true);
    expect(result.verifiedIndices).toEqual([0, 1]);

    // Now with threshold too high
    const result2 = await validateSigs(
      crypto,
      message,
      sigers,
      [kp0.verferQb64, kp1.verferQb64],
      "3",
    );
    expect(result2.satisfied).toBe(false);
  });
});
