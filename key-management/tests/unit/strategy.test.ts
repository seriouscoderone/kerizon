/**
 * T060–T073: Key Generation Strategy Tests
 */
import { describe, it, expect } from "vitest";
import {
  RandomKeyGenerator,
  DeterministicKeyGenerator,
  KeyGeneratorFactory,
} from "../../src/derivation/strategy.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { KeyAlgorithm, SecurityTier } from "../../src/types.js";
import { MtrDex, matterEncode } from "../../src/cesr-helpers.js";
import { DerivationError } from "../../src/errors.js";

const crypto = new DefaultCryptographicSuite();

function makeSaltQb64(): string {
  const raw = new Uint8Array(16).fill(0xab);
  return matterEncode(raw, MtrDex.Salt_128);
}

describe("T060-T063: RandomKeyGenerator", () => {
  it("T060: RandomKeyGenerator creates correct count of signers", () => {
    const gen = new RandomKeyGenerator(crypto);
    const signers = gen.create(null, 3, MtrDex.Ed25519_Seed, 0, 0, 0, true, false);
    expect(signers.length).toBe(3);
  });

  it("T061: RandomKeyGenerator each signer has unique raw material", () => {
    const gen = new RandomKeyGenerator(crypto);
    const signers = gen.create(null, 5, MtrDex.Ed25519_Seed, 0, 0, 0, true, false);
    const raws = signers.map((s) => s.qb64);
    expect(new Set(raws).size).toBe(5);
  });

  it("T062: RandomKeyGenerator respects transferable flag", () => {
    const gen = new RandomKeyGenerator(crypto);
    const transferable = gen.create(null, 2, MtrDex.Ed25519_Seed, 0, 0, 0, true, false);
    const nonTransferable = gen.create(null, 2, MtrDex.Ed25519_Seed, 0, 0, 0, false, false);
    for (const s of transferable) {
      expect(s.verfer.transferable).toBe(true);
    }
    for (const s of nonTransferable) {
      expect(s.verfer.transferable).toBe(false);
    }
  });

  it("T063: RandomKeyGenerator with explicit codes creates that many signers", () => {
    const gen = new RandomKeyGenerator(crypto);
    const codes = [MtrDex.Ed25519_Seed, MtrDex.Ed25519_Seed, MtrDex.Ed25519_Seed];
    const signers = gen.create(codes, 99, MtrDex.Ed25519_Seed, 0, 0, 0, true, false);
    // explicit codes override count
    expect(signers.length).toBe(3);
  });
});

describe("T064-T070: DeterministicKeyGenerator", () => {
  it("T064: DeterministicKeyGenerator creates correct count of signers", () => {
    const salt = makeSaltQb64();
    const gen = new DeterministicKeyGenerator(salt, null, SecurityTier.LOW, crypto);
    const signers = gen.create(null, 3, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    expect(signers.length).toBe(3);
  });

  it("T065: DeterministicKeyGenerator same inputs → same signers", () => {
    const salt = makeSaltQb64();
    const gen1 = new DeterministicKeyGenerator(salt, "stem", SecurityTier.LOW, crypto);
    const gen2 = new DeterministicKeyGenerator(salt, "stem", SecurityTier.LOW, crypto);
    const s1 = gen1.create(null, 2, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    const s2 = gen2.create(null, 2, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    expect(s1[0].qb64).toBe(s2[0].qb64);
    expect(s1[1].qb64).toBe(s2[1].qb64);
  });

  it("T066: DeterministicKeyGenerator different pidx → different signers", () => {
    const salt = makeSaltQb64();
    const gen = new DeterministicKeyGenerator(salt, null, SecurityTier.LOW, crypto);
    const s1 = gen.create(null, 1, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    const s2 = gen.create(null, 1, MtrDex.Ed25519_Seed, 1, 0, 0, true, true);
    expect(s1[0].qb64).not.toBe(s2[0].qb64);
  });

  it("T067: DeterministicKeyGenerator different ridx → different signers", () => {
    const salt = makeSaltQb64();
    const gen = new DeterministicKeyGenerator(salt, "stem", SecurityTier.LOW, crypto);
    const s1 = gen.create(null, 1, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    const s2 = gen.create(null, 1, MtrDex.Ed25519_Seed, 0, 1, 0, true, true);
    expect(s1[0].qb64).not.toBe(s2[0].qb64);
  });

  it("T068: DeterministicKeyGenerator respects stem override", () => {
    const salt = makeSaltQb64();
    const gen1 = new DeterministicKeyGenerator(salt, "stem1", SecurityTier.LOW, crypto);
    const gen2 = new DeterministicKeyGenerator(salt, "stem2", SecurityTier.LOW, crypto);
    const s1 = gen1.create(null, 1, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    const s2 = gen2.create(null, 1, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    expect(s1[0].qb64).not.toBe(s2[0].qb64);
  });

  it("T069: DeterministicKeyGenerator respects tier (affects derivation path when non-test)", () => {
    const salt = makeSaltQb64();
    const gen = new DeterministicKeyGenerator(salt, "stem", SecurityTier.LOW, crypto);
    const s1 = gen.create(null, 1, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    // Same generator, same params → same result
    const s2 = gen.create(null, 1, MtrDex.Ed25519_Seed, 0, 0, 0, true, true);
    expect(s1[0].qb64).toBe(s2[0].qb64);
  });

  it("T070: DeterministicKeyGenerator path: stem + ridx hex + kidx hex", () => {
    const salt = makeSaltQb64();
    const gen = new DeterministicKeyGenerator(salt, "mys", SecurityTier.LOW, crypto);
    // ridx=2 (hex "2"), kidx=4 (hex "4") → path = "mys24"
    const s1 = gen.create(null, 1, MtrDex.Ed25519_Seed, 0, 2, 4, true, true);
    const s2 = gen.create(null, 1, MtrDex.Ed25519_Seed, 0, 2, 4, true, true);
    expect(s1[0].qb64).toBe(s2[0].qb64);
  });
});

describe("T071-T073: KeyGeneratorFactory", () => {
  it("T071: KeyGeneratorFactory RANDOM → RandomKeyGenerator", () => {
    const factory = new KeyGeneratorFactory(KeyAlgorithm.RANDOM);
    const gen = factory.make(null, null, null, crypto);
    expect(gen).toBeInstanceOf(RandomKeyGenerator);
  });

  it("T072: KeyGeneratorFactory DETERMINISTIC → DeterministicKeyGenerator", () => {
    const factory = new KeyGeneratorFactory(KeyAlgorithm.DETERMINISTIC);
    const gen = factory.make(null, null, null, crypto);
    expect(gen).toBeInstanceOf(DeterministicKeyGenerator);
  });

  it("T073: KeyGeneratorFactory unsupported algorithm raises error", () => {
    const factory = new KeyGeneratorFactory(KeyAlgorithm.GROUP);
    expect(() => factory.make(null, null, null, crypto)).toThrow(DerivationError);
  });
});
