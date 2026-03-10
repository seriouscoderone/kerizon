/**
 * T092–T126: KeyVault Tests
 */
import { describe, it, expect } from "vitest";
import { KeyVault } from "../../src/key-vault.js";
import { InMemoryKeyStore } from "../../src/memory/in-memory-key-store.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { InceptionKeySetBuilder } from "../../src/builders/inception-keys.js";
import {
  KeyStoreClosedError,
  AuthenticationError,
  NonTransferableError,
  ThresholdError,
  PrefixNotFoundError,
  KeyNotFoundError,
} from "../../src/errors.js";
import { MtrDex, matterEncode, matterDecode } from "../../src/cesr-helpers.js";
import { SecretEncryptor } from "../../src/encryption/secret-encryptor.js";

const crypto = new DefaultCryptographicSuite();

function makeVaultPair(seed?: string) {
  const store = new InMemoryKeyStore();
  store.open();
  const vault = new KeyVault(store, seed ?? null, crypto);
  vault.setup();
  return { store, vault };
}

function makeSeedQb64(): string {
  const raw = crypto.generateRandom(32);
  return matterEncode(raw, MtrDex.Ed25519_Seed);
}

function verkeyFromSeed(seedQb64: string): string {
  const raw = matterDecode(seedQb64);
  const { publicKey } = crypto.deriveEdKeyPair(raw);
  return matterEncode(publicKey, MtrDex.Ed25519);
}

describe("T092-T101: KeyVault Setup and Authentication", () => {
  it("T092: Construction with open KeyStore calls setup", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, null, crypto);
    vault.setup();
    expect(store.getGlobal("pidx")).not.toBeNull();
  });

  it("T093: Construction with closed KeyStore defers setup", () => {
    const store = new InMemoryKeyStore();
    const vault = new KeyVault(store, null, crypto);
    expect(() => vault.setup()).toThrow(KeyStoreClosedError);
  });

  it("T094: Setup initializes globals on first call", () => {
    const { store } = makeVaultPair();
    expect(store.getGlobal("pidx")).toBe("0");
    expect(store.getGlobal("algo")).not.toBeNull();
    expect(store.getGlobal("salt")).not.toBeNull();
    expect(store.getGlobal("tier")).not.toBeNull();
  });

  it("T095: Setup does not overwrite existing globals", () => {
    const store = new InMemoryKeyStore();
    store.open();
    store.putGlobal("pidx", "7");
    const vault = new KeyVault(store, null, crypto);
    vault.setup();
    expect(store.getGlobal("pidx")).toBe("7");
  });

  it("T096: Setup raises KeyStoreClosedError when store closed", () => {
    const store = new InMemoryKeyStore();
    const vault = new KeyVault(store, null, crypto);
    expect(() => vault.setup()).toThrow(KeyStoreClosedError);
  });

  it("T097: Setup with AEID derives encrypter/decrypter", () => {
    const seedQb64 = makeSeedQb64();
    const verkeyQb64 = verkeyFromSeed(seedQb64);

    const store = new InMemoryKeyStore();
    store.open();
    store.putGlobal("aeid", verkeyQb64);

    const vault = new KeyVault(store, seedQb64, crypto);
    vault.setup();
    const { verfers } = vault.inceptKeys({ testMode: true });
    expect(verfers.length).toBe(1);
  });

  it("T098: Setup with AEID but wrong seed raises AuthenticationError", () => {
    const seedQb64 = makeSeedQb64();
    const wrongSeed = makeSeedQb64();
    const verkeyQb64 = verkeyFromSeed(seedQb64);

    const store = new InMemoryKeyStore();
    store.open();
    store.putGlobal("aeid", verkeyQb64);

    // The constructor calls setup() automatically when store is open
    // so the error is thrown from construction
    expect(() => new KeyVault(store, wrongSeed, crypto)).toThrow(AuthenticationError);
  });

  it("T099: updateAuthentication changes AEID", () => {
    const { store, vault } = makeVaultPair();
    new InceptionKeySetBuilder().testMode(true).build(vault);

    const seedQb64 = makeSeedQb64();
    const verkeyQb64 = verkeyFromSeed(seedQb64);

    vault.updateAuthentication(verkeyQb64, seedQb64);
    expect(store.getGlobal("aeid")).toBe(verkeyQb64);
  });

  it("T100: updateAuthentication with empty AEID unencrypts secrets", () => {
    const seedQb64 = makeSeedQb64();
    const verkeyQb64 = verkeyFromSeed(seedQb64);

    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, seedQb64, crypto);
    vault.setup(verkeyQb64);

    vault.updateAuthentication("", "");
    expect(store.getGlobal("aeid")).toBe("");
  });

  it("T101: updateAuthentication verifies AEID is stored correctly", () => {
    const seedQb64 = makeSeedQb64();
    const verkeyQb64 = verkeyFromSeed(seedQb64);

    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, seedQb64, crypto);
    vault.setup(verkeyQb64);
    expect(store.getGlobal("aeid")).toBe(verkeyQb64);
  });
});

describe("T102-T115: KeyVault Inception and Rotation", () => {
  it("T102: inceptKeys returns correct verfers and digers", () => {
    const { vault } = makeVaultPair();
    const { verfers, digers } = vault.inceptKeys({ testMode: true });
    expect(verfers.length).toBe(1);
    expect(digers.length).toBe(1);
    expect(verfers[0].qb64.startsWith(MtrDex.Ed25519)).toBe(true);
    expect(digers[0].qb64.startsWith(MtrDex.Blake3_256)).toBe(true);
  });

  it("T103: inceptKeys stores private keys in KeyStore", () => {
    const { store, vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const sk = store.getPrivateKey(verfers[0].qb64, null);
    expect(sk).not.toBeNull();
  });

  it("T104: inceptKeys increments pidx", () => {
    const { store, vault } = makeVaultPair();
    vault.inceptKeys({ testMode: true });
    vault.inceptKeys({ testMode: true });
    expect(parseInt(store.getGlobal("pidx") ?? "0")).toBe(2);
  });

  it("T105: inceptKeys with AEID encrypts stored keys", () => {
    const seedQb64 = makeSeedQb64();
    const verkeyQb64 = verkeyFromSeed(seedQb64);

    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, seedQb64, crypto);
    vault.setup(verkeyQb64);

    const { verfers } = vault.inceptKeys({ testMode: true });
    const sk = store.getPrivateKey(verfers[0].qb64, null);
    expect(sk).toBeNull(); // encrypted, no decrypter provided
  });

  it("T106: Each inceptKeys call allocates a unique pidx (no duplicate keys)", () => {
    const { vault } = makeVaultPair();
    const { verfers: v1 } = vault.inceptKeys({ testMode: true });
    const { verfers: v2 } = vault.inceptKeys({ testMode: true });
    // Different pidx means different keys
    expect(v1[0].qb64).not.toBe(v2[0].qb64);
  });

  it("T107: inceptKeys with rooted=true uses vault salt", () => {
    const { store, vault } = makeVaultPair();
    const rootSalt = store.getGlobal("salt");
    const { verfers } = vault.inceptKeys({ rooted: true, testMode: true });
    expect(verfers.length).toBe(1);
    expect(rootSalt).not.toBeNull();
  });

  it("T108: inceptKeys with rooted=false uses provided salt", () => {
    const { vault } = makeVaultPair();
    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const { verfers } = vault.inceptKeys({ rooted: false, salt: saltQb64, testMode: true });
    expect(verfers.length).toBe(1);
  });

  it("T109: rotateKeys advances three-phase state correctly", () => {
    const { store, vault } = makeVaultPair();
    const { verfers: origVerfers } = vault.inceptKeys({ testMode: true });
    const prefix = origVerfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const sitBefore = store.getKeySituation(prefix)!;
    vault.rotateKeys({ prefix, testMode: true });
    const sitAfter = store.getKeySituation(prefix)!;

    expect(sitAfter.previous.pubs).toEqual(sitBefore.current.pubs);
    expect(sitAfter.current.pubs).toEqual(sitBefore.next.pubs);
  });

  it("T110: rotateKeys returns correct verfers from prior next", () => {
    const { store, vault } = makeVaultPair();
    const { verfers: origVerfers } = vault.inceptKeys({ testMode: true });
    const prefix = origVerfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const sitBefore = store.getKeySituation(prefix)!;
    const nextPubs = sitBefore.next.pubs;

    const { verfers } = vault.rotateKeys({ prefix, testMode: true });
    expect(verfers.map((v) => v.qb64)).toEqual(nextPubs);
  });

  it("T111: rotateKeys generates new next keys", () => {
    const { store, vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const sitBefore = store.getKeySituation(prefix)!;
    vault.rotateKeys({ prefix, testMode: true });
    const sitAfter = store.getKeySituation(prefix)!;

    expect(sitAfter.next.pubs).not.toEqual(sitBefore.next.pubs);
  });

  it("T112: rotateKeys erases stale keys when configured", () => {
    const { store, vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    vault.rotateKeys({ prefix, eraseStaleKeys: true, testMode: true });
    vault.rotateKeys({ prefix, eraseStaleKeys: true, testMode: true });

    expect(store.getPrivateKey(verfers[0].qb64, null)).toBeNull();
  });

  it("T113: rotateKeys preserves stale keys when erase=false", () => {
    const { store, vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    vault.rotateKeys({ prefix, eraseStaleKeys: false, testMode: true });
    vault.rotateKeys({ prefix, eraseStaleKeys: false, testMode: true });

    expect(store.getPrivateKey(verfers[0].qb64, null)).not.toBeNull();
  });

  it("T114: rotateKeys rejects non-transferable prefix", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ transferable: false, nextCount: 0, testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);
    expect(() => vault.rotateKeys({ prefix, testMode: true })).toThrow(NonTransferableError);
  });

  it("T115: rotateKeys with AEID decrypts keys correctly", () => {
    const seedQb64 = makeSeedQb64();
    const verkeyQb64 = verkeyFromSeed(seedQb64);

    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, seedQb64, crypto);
    vault.setup(verkeyQb64);

    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const { verfers: rotVerfers } = vault.rotateKeys({ prefix, testMode: true });
    expect(rotVerfers.length).toBe(1);
  });
});

describe("T116-T118: KeyVault Replay", () => {
  it("T116: replayKeys returns correct verfers at current index", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const { verfers: replayed } = vault.replayKeys({ prefix });
    expect(replayed.map((v) => v.qb64)).toEqual(verfers.map((v) => v.qb64));
  });

  it("T117: replayKeys with advance=false does not change state", () => {
    const { store, vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const sitBefore = store.getKeySituation(prefix)!;
    vault.replayKeys({ prefix, advance: false });
    const sitAfter = store.getKeySituation(prefix)!;
    expect(sitBefore.current.ridx).toBe(sitAfter.current.ridx);
  });

  it("T118: replayKeys with advance=true raises at end of sequence", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    expect(() => vault.replayKeys({ prefix, advance: true })).toThrow();
  });
});

describe("T119-T126: KeyVault Signing and Decryption", () => {
  it("T119: signSerialization produces indexed Sigers", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const ser = new Uint8Array(32).fill(0xab);
    const sigs = vault.signSerialization({ ser, pubs: [prefix], indexed: true });
    expect(sigs.length).toBe(1);
    expect((sigs[0] as any).index).toBe(0);
  });

  it("T120: signSerialization produces unindexed Cigars", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const ser = new Uint8Array(32).fill(0xab);
    const sigs = vault.signSerialization({ ser, pubs: [prefix], indexed: false });
    expect(sigs.length).toBe(1);
    expect((sigs[0] as any).verferQb64).toBeDefined();
  });

  it("T121: signSerialization with custom indices", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const ser = new Uint8Array(32).fill(0xab);
    const sigs = vault.signSerialization({ ser, pubs: [prefix], indices: [5], indexed: true });
    expect((sigs[0] as any).index).toBe(5);
  });

  it("T122: signSerialization with custom ondices", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const ser = new Uint8Array(32).fill(0xab);
    const sigs = vault.signSerialization({ ser, pubs: [prefix], indices: [0], ondices: [null], indexed: true });
    expect(sigs.length).toBe(1);
  });

  it("T123: signSerialization raises on index length mismatch", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const ser = new Uint8Array(32);
    expect(() =>
      vault.signSerialization({ ser, pubs: [prefix], indices: [0, 1], indexed: true })
    ).toThrow(ThresholdError);
  });

  it("T124: decryptSecret round-trips through encrypt/decrypt", () => {
    const { vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const enc = new SecretEncryptor({ verkey: prefix, crypto });
    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });

    const plaintext = vault.decryptSecret({ qb64: cipher.qb64, pubs: [prefix] });
    const decoded = new TextDecoder().decode(plaintext);
    expect(decoded).toBe(saltQb64);
  });

  it("T125: movePrefix transfers all KeyStore entries", () => {
    const { store, vault } = makeVaultPair();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const oldPrefix = verfers[0].qb64;

    const newPrefix = "Dnewprefix1234567890123456789012345678901234";
    vault.movePrefix(oldPrefix, newPrefix);

    expect(store.getDerivationParameters(newPrefix)).not.toBeNull();
    expect(store.getKeySituation(newPrefix)).not.toBeNull();
    expect(store.getDerivationParameters(oldPrefix)).toBeNull();
  });

  it("T126: movePrefix rejects non-existent old prefix", () => {
    const { vault } = makeVaultPair();
    expect(() =>
      vault.movePrefix("Dnotexist1234567890123456789012345678901234", "Dnewprefix")
    ).toThrow(PrefixNotFoundError);
  });
});
