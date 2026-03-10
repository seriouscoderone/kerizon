/**
 * T044–T059: Encryption / Decryption Tests
 */
import { describe, it, expect } from "vitest";
import { SecretEncryptor } from "../../src/encryption/secret-encryptor.js";
import { SecretDecryptor } from "../../src/encryption/secret-decryptor.js";
import { KeyDeriver } from "../../src/derivation/key-deriver.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { MtrDex, matterEncode } from "../../src/cesr-helpers.js";
import { DerivationError } from "../../src/errors.js";
import { makeSigningKey } from "../../src/signing-key.js";

const crypto = new DefaultCryptographicSuite();

/** Create a seed + verkey pair for testing. */
function makeTestKeypair() {
  const seedRaw = crypto.generateRandom(32);
  const seedQb64 = matterEncode(seedRaw, MtrDex.Ed25519_Seed);
  const { publicKey } = crypto.deriveEdKeyPair(seedRaw);
  const verkeyQb64 = matterEncode(publicKey, MtrDex.Ed25519);
  return { seedRaw, seedQb64, publicKey, verkeyQb64 };
}

describe("T044-T050: SecretEncryptor", () => {
  it("T044: SecretEncryptor construction from Ed25519 verkey", () => {
    const { verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    expect(enc.raw.length).toBe(32);
    expect(enc.qb64.startsWith(MtrDex.X25519)).toBe(true);
  });

  it("T045: SecretEncryptor rejects non-Ed25519 verkey", () => {
    // Use a salt code which isn't Ed25519
    const saltRaw = new Uint8Array(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    expect(() => new SecretEncryptor({ verkey: saltQb64, crypto })).toThrow(DerivationError);
  });

  it("T046: Encrypt salt produces X25519_Cipher_Salt cipher", () => {
    const { verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });
    expect(cipher.code).toBe(MtrDex.X25519_Cipher_Salt);
    expect(cipher.raw.length).toBe(72);
  });

  it("T047: Encrypt seed produces X25519_Cipher_Seed cipher", () => {
    const { verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const seedRaw = crypto.generateRandom(32);
    const seedQb64 = matterEncode(seedRaw, MtrDex.Ed25519_Seed);
    const cipher = enc.encrypt(undefined, { raw: seedRaw, qb64: seedQb64, code: MtrDex.Ed25519_Seed });
    expect(cipher.code).toBe(MtrDex.X25519_Cipher_Seed);
    expect(cipher.raw.length).toBe(92);
  });

  it("T048: Encrypt with explicit code overrides auto-detection (ser path)", () => {
    const { verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    // Encrypt arbitrary ser bytes with explicit cipher code for seed
    const ser = new Uint8Array(44).fill(0x41); // 44 bytes to match seed size
    // This should accept the explicit code for a custom ser encryption
    // The raw would be 44+48=92 bytes
    const cipher = enc.encrypt(ser, undefined, MtrDex.X25519_Cipher_Seed);
    expect(cipher.code).toBe(MtrDex.X25519_Cipher_Seed);
  });

  it("T049: verifySeed returns true for matching seed", () => {
    const { seedQb64, verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    expect(enc.verifySeed(seedQb64)).toBe(true);
  });

  it("T050: verifySeed returns false for mismatched seed", () => {
    const { verkeyQb64 } = makeTestKeypair();
    const { seedQb64: wrongSeed } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    expect(enc.verifySeed(wrongSeed)).toBe(false);
  });
});

describe("T051-T059: SecretDecryptor", () => {
  it("T051: SecretDecryptor construction from seed", () => {
    const { seedQb64 } = makeTestKeypair();
    const dec = new SecretDecryptor({ seed: seedQb64, crypto });
    expect(dec.raw.length).toBe(32);
    expect(dec.qb64.startsWith(MtrDex.X25519_Private)).toBe(true);
  });

  it("T052: SecretDecryptor rejects non-Ed25519 seed", () => {
    const saltRaw = new Uint8Array(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    expect(() => new SecretDecryptor({ seed: saltQb64, crypto })).toThrow(DerivationError);
  });

  it("T053: Decrypt salt cipher returns KeyDeriver", () => {
    const { seedQb64, verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const dec = new SecretDecryptor({ seed: seedQb64, crypto });

    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });

    const result = dec.decrypt(cipher);
    expect(result).toBeInstanceOf(KeyDeriver);
  });

  it("T054: Decrypt seed cipher returns SigningKey", () => {
    const { seedQb64, verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const dec = new SecretDecryptor({ seed: seedQb64, crypto });

    const { seedRaw, seedQb64: targetSeedQb64 } = makeTestKeypair();
    const cipher = enc.encrypt(undefined, { raw: seedRaw, qb64: targetSeedQb64, code: MtrDex.Ed25519_Seed });

    const result = dec.decrypt(cipher);
    expect((result as any).verfer).toBeDefined(); // SigningKey has verfer
  });

  it("T055: Decrypt with bare=true returns raw bytes", () => {
    const { seedQb64, verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const dec = new SecretDecryptor({ seed: seedQb64, crypto });

    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });

    const result = dec.decrypt(cipher, undefined, undefined, true, true);
    expect(result).toBeInstanceOf(Uint8Array);
    // The raw bytes are the UTF-8 encoding of the salt qb64
    const decoded = new TextDecoder().decode(result as Uint8Array);
    expect(decoded).toBe(saltQb64);
  });

  it("T056: Decrypt with explicit klas overrides auto-detection", () => {
    const { seedQb64, verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const dec = new SecretDecryptor({ seed: seedQb64, crypto });

    // Encrypt a seed cipher but decrypt as salt
    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });

    // Explicitly force "salt" klas
    const result = dec.decrypt(cipher, undefined, "salt");
    expect(result).toBeInstanceOf(KeyDeriver);
  });

  it("T057: Round-trip: encrypt(salt) → decrypt → original salt", () => {
    const { seedQb64, verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const dec = new SecretDecryptor({ seed: seedQb64, crypto });

    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });

    const deriver = dec.decrypt(cipher) as KeyDeriver;
    expect(deriver.qb64).toBe(saltQb64);
    expect(deriver.raw).toEqual(saltRaw);
  });

  it("T058: Round-trip: encrypt(seed) → decrypt → original signing key", () => {
    const { seedQb64, verkeyQb64 } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const dec = new SecretDecryptor({ seed: seedQb64, crypto });

    const targetSeedRaw = crypto.generateRandom(32);
    const targetSeedQb64 = matterEncode(targetSeedRaw, MtrDex.Ed25519_Seed);
    const cipher = enc.encrypt(undefined, {
      raw: targetSeedRaw,
      qb64: targetSeedQb64,
      code: MtrDex.Ed25519_Seed,
    });

    const sk = dec.decrypt(cipher) as ReturnType<typeof makeSigningKey>;
    expect(sk.raw).toEqual(targetSeedRaw);
    expect(sk.qb64).toBe(targetSeedQb64);
  });

  it("T059: Decrypt with wrong key fails", () => {
    const { seedQb64, verkeyQb64 } = makeTestKeypair();
    const { seedQb64: wrongSeed } = makeTestKeypair();
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const dec = new SecretDecryptor({ seed: wrongSeed, crypto });

    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });

    expect(() => dec.decrypt(cipher)).toThrow();
  });
});
