import { describe, it, expect, beforeAll } from "vitest";
import { evaluateThreshold } from "../../src/core/ThresholdEvaluator.js";
import {
  generateKeyPair,
  signMessage,
  encodeEd25519IndexedSig,
  encodeEd25519Verfer,
  makeKeyState,
} from "../helpers.js";
import type { KeyState } from "../../src/types/KeyState.js";
import type { IndexedSig, CoupledSig } from "../../src/core/AttachmentParser.js";

const message = new TextEncoder().encode("test-message-for-threshold");

describe("ThresholdEvaluator — simple threshold", () => {
  it("returns true when exactly the required number of sigs are valid (1-of-1)", async () => {
    const kp = await generateKeyPair();
    const ks: KeyState = {
      currentKeys: [kp.verferQb64],
      threshold: "1",
      sn: 0n,
      witnessAids: [],
    };
    const sigBytes = await signMessage(kp.privateKey, message);
    const indexed: IndexedSig = {
      index: 0,
      raw: sigBytes,
      qb64: encodeEd25519IndexedSig(sigBytes, 0),
    };
    const result = await evaluateThreshold({
      indexedSigs: [indexed],
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(true);
  });

  it("returns false when no sigs are provided for threshold 1", async () => {
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    const result = await evaluateThreshold({
      indexedSigs: [],
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(false);
  });

  it("returns false when signature is for a different message", async () => {
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    const wrongMessage = new TextEncoder().encode("different-message");
    const sigBytes = await signMessage(kp.privateKey, wrongMessage);
    const indexed: IndexedSig = {
      index: 0,
      raw: sigBytes,
      qb64: encodeEd25519IndexedSig(sigBytes, 0),
    };
    const result = await evaluateThreshold({
      indexedSigs: [indexed],
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(false);
  });

  it("returns false when signature is from a different key", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const ks = makeKeyState(kp1.verferQb64);
    const sigBytes = await signMessage(kp2.privateKey, message);
    const indexed: IndexedSig = {
      index: 0,
      raw: sigBytes,
      qb64: encodeEd25519IndexedSig(sigBytes, 0),
    };
    const result = await evaluateThreshold({
      indexedSigs: [indexed],
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(false);
  });

  it("satisfies 2-of-3 threshold with exactly 2 valid sigs", async () => {
    const [kp0, kp1, kp2] = await Promise.all([
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ]);
    const ks: KeyState = {
      currentKeys: [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
      threshold: "2",
      sn: 0n,
      witnessAids: [],
    };
    const sig0 = await signMessage(kp0.privateKey, message);
    const sig1 = await signMessage(kp1.privateKey, message);
    const indexedSigs: IndexedSig[] = [
      { index: 0, raw: sig0, qb64: encodeEd25519IndexedSig(sig0, 0) },
      { index: 1, raw: sig1, qb64: encodeEd25519IndexedSig(sig1, 1) },
    ];
    const result = await evaluateThreshold({
      indexedSigs,
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(true);
  });

  it("fails 2-of-3 threshold with only 1 valid sig", async () => {
    const [kp0, kp1, kp2] = await Promise.all([
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ]);
    const ks: KeyState = {
      currentKeys: [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64],
      threshold: "2",
      sn: 0n,
      witnessAids: [],
    };
    const sig0 = await signMessage(kp0.privateKey, message);
    const indexedSigs: IndexedSig[] = [
      { index: 0, raw: sig0, qb64: encodeEd25519IndexedSig(sig0, 0) },
    ];
    const result = await evaluateThreshold({
      indexedSigs,
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(false);
  });

  it("satisfies threshold via CoupledSig (non-transferable receipt)", async () => {
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    const sigBytes = await signMessage(kp.privateKey, message);
    const coupled: CoupledSig = {
      verferQb64: kp.verferQb64,
      verferRaw: kp.publicKeyBytes,
      sigRaw: sigBytes,
      sigQb64: encodeEd25519IndexedSig(sigBytes, 0),
    };
    const result = await evaluateThreshold({
      indexedSigs: [],
      coupledSigs: [coupled],
      message,
      keyState: ks,
    });
    expect(result).toBe(true);
  });
});

describe("ThresholdEvaluator — weighted threshold", () => {
  it("satisfies weighted threshold [['1/2','1/2']] with both keys", async () => {
    const [kp0, kp1] = await Promise.all([generateKeyPair(), generateKeyPair()]);
    const ks: KeyState = {
      currentKeys: [kp0.verferQb64, kp1.verferQb64],
      threshold: [["1/2", "1/2"]],
      sn: 0n,
      witnessAids: [],
    };
    const sig0 = await signMessage(kp0.privateKey, message);
    const sig1 = await signMessage(kp1.privateKey, message);
    const indexedSigs: IndexedSig[] = [
      { index: 0, raw: sig0, qb64: encodeEd25519IndexedSig(sig0, 0) },
      { index: 1, raw: sig1, qb64: encodeEd25519IndexedSig(sig1, 1) },
    ];
    const result = await evaluateThreshold({
      indexedSigs,
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(true);
  });

  it("fails weighted threshold [['1/2','1/2']] with only one key", async () => {
    const [kp0, kp1] = await Promise.all([generateKeyPair(), generateKeyPair()]);
    const ks: KeyState = {
      currentKeys: [kp0.verferQb64, kp1.verferQb64],
      threshold: [["1/2", "1/2"]],
      sn: 0n,
      witnessAids: [],
    };
    const sig0 = await signMessage(kp0.privateKey, message);
    const indexedSigs: IndexedSig[] = [
      { index: 0, raw: sig0, qb64: encodeEd25519IndexedSig(sig0, 0) },
    ];
    const result = await evaluateThreshold({
      indexedSigs,
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(false);
  });

  it("satisfies two-group weighted threshold when both groups pass", async () => {
    // Group 0: kp0 + kp1 each 1/2 (need both)
    // Group 1: kp2 + kp3 each 1/2 (need both)
    const [kp0, kp1, kp2, kp3] = await Promise.all([
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ]);
    const ks: KeyState = {
      currentKeys: [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64, kp3.verferQb64],
      threshold: [
        ["1/2", "1/2"],
        ["1/2", "1/2"],
      ],
      sn: 0n,
      witnessAids: [],
    };
    const [s0, s1, s2, s3] = await Promise.all([
      signMessage(kp0.privateKey, message),
      signMessage(kp1.privateKey, message),
      signMessage(kp2.privateKey, message),
      signMessage(kp3.privateKey, message),
    ]);
    const indexedSigs: IndexedSig[] = [
      { index: 0, raw: s0, qb64: encodeEd25519IndexedSig(s0, 0) },
      { index: 1, raw: s1, qb64: encodeEd25519IndexedSig(s1, 1) },
      { index: 2, raw: s2, qb64: encodeEd25519IndexedSig(s2, 2) },
      { index: 3, raw: s3, qb64: encodeEd25519IndexedSig(s3, 3) },
    ];
    const result = await evaluateThreshold({
      indexedSigs,
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(true);
  });

  it("fails two-group weighted threshold when one group is missing a key", async () => {
    const [kp0, kp1, kp2, kp3] = await Promise.all([
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ]);
    const ks: KeyState = {
      currentKeys: [kp0.verferQb64, kp1.verferQb64, kp2.verferQb64, kp3.verferQb64],
      threshold: [
        ["1/2", "1/2"],
        ["1/2", "1/2"],
      ],
      sn: 0n,
      witnessAids: [],
    };
    // Only sign with kp0, kp1 (group 0 passes, group 1 missing)
    const [s0, s1] = await Promise.all([
      signMessage(kp0.privateKey, message),
      signMessage(kp1.privateKey, message),
    ]);
    const indexedSigs: IndexedSig[] = [
      { index: 0, raw: s0, qb64: encodeEd25519IndexedSig(s0, 0) },
      { index: 1, raw: s1, qb64: encodeEd25519IndexedSig(s1, 1) },
    ];
    const result = await evaluateThreshold({
      indexedSigs,
      coupledSigs: [],
      message,
      keyState: ks,
    });
    expect(result).toBe(false);
  });
});
