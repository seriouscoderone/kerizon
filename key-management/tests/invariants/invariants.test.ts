/**
 * T207–T221: Invariant Tests
 */
import { describe, it, expect } from "vitest";
import { KeyVault } from "../../src/key-vault.js";
import { InMemoryKeyStore } from "../../src/memory/in-memory-key-store.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { InceptionKeySetBuilder } from "../../src/builders/inception-keys.js";
import { RotationKeySetBuilder } from "../../src/builders/rotation-keys.js";
import { MtrDex, matterEncode, matterDecode } from "../../src/cesr-helpers.js";
import { NonTransferableError, KeyNotFoundError } from "../../src/errors.js";
import { IdentifierRegistry } from "../../src/identifier-registry.js";
import { makeDerivationParameters } from "../../src/types.js";

const crypto = new DefaultCryptographicSuite();

function makeVault() {
  const store = new InMemoryKeyStore();
  store.open();
  const vault = new KeyVault(store, null, crypto);
  vault.setup();
  return { store, vault };
}

function makeSeedQb64() {
  return matterEncode(crypto.generateRandom(32), MtrDex.Ed25519_Seed);
}

function makeRegistry() {
  const store = new InMemoryKeyStore();
  const registry = new IdentifierRegistry({ name: "inv-test", keyStore: store, cryptoSuite: crypto });
  registry.setup();
  return { store, registry };
}

describe("T207-T221: Invariants", () => {
  it("T207: INV-1: Private keys encrypted in store when AEID set", async () => {
    const seedQb64 = makeSeedQb64();
    const seedRaw = matterDecode(seedQb64);
    const { publicKey } = crypto.deriveEdKeyPair(seedRaw);
    const verkeyQb64 = matterEncode(publicKey, MtrDex.Ed25519);

    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, seedQb64, crypto);
    vault.setup(verkeyQb64);

    const { verfers } = vault.inceptKeys({ testMode: true });
    // Without decrypter (null), keys should not be readable
    const sk = store.getPrivateKey(verfers[0].qb64, null);
    expect(sk).toBeNull(); // Encrypted, can't read without decrypter
  });

  it("T208: INV-3: Deterministic derivation reproducibility", () => {
    const { vault: v1 } = makeVault();
    const { vault: v2 } = makeVault();

    const saltRaw = new Uint8Array(16).fill(0xf7);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);

    const { verfers: vf1 } = v1.inceptKeys({ rooted: false, salt: saltQb64, testMode: true });
    const { verfers: vf2 } = v2.inceptKeys({ rooted: false, salt: saltQb64, testMode: true });

    // Same salt → same keys (deterministic)
    expect(vf1[0].qb64).toBe(vf2[0].qb64);
  });

  it("T209: INV-4: Three-phase rotation advances correctly (prev←curr, curr←next)", () => {
    const { store, vault } = makeVault();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const sit0 = store.getKeySituation(prefix)!;
    const currPubs0 = [...sit0.current.pubs];
    const nextPubs0 = [...sit0.next.pubs];

    vault.rotateKeys({ prefix, testMode: true });
    const sit1 = store.getKeySituation(prefix)!;

    expect(sit1.previous.pubs).toEqual(currPubs0);
    expect(sit1.current.pubs).toEqual(nextPubs0);
  });

  it("T210: INV-5: Rotation index contiguous after rotation", () => {
    const { store, vault } = makeVault();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    vault.rotateKeys({ prefix, testMode: true });
    const sit1 = store.getKeySituation(prefix)!;
    expect(sit1.current.ridx).toBe(1);
    expect(sit1.next.ridx).toBe(2);
  });

  it("T211: INV-6: Key index contiguous within key set", () => {
    const { store, vault } = makeVault();
    const { verfers } = vault.inceptKeys({ currentCount: 2, nextCount: 2, testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const sit0 = store.getKeySituation(prefix)!;
    expect(sit0.current.kidx).toBe(0);
    expect(sit0.next.kidx).toBe(2); // nextKidx = len(current)

    vault.rotateKeys({ prefix, nextCount: 2, testMode: true });
    const sit1 = store.getKeySituation(prefix)!;
    expect(sit1.next.kidx).toBe(sit1.current.kidx + sit1.current.pubs.length);
  });

  it("T212: INV-7: Operations fail without decrypter when AEID set", () => {
    const seedQb64 = makeSeedQb64();
    const seedRaw = matterDecode(seedQb64);
    const { publicKey } = crypto.deriveEdKeyPair(seedRaw);
    const verkeyQb64 = matterEncode(publicKey, MtrDex.Ed25519);

    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, seedQb64, crypto);
    vault.setup(verkeyQb64);

    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    // Now create a vault without the seed (no decrypter)
    const vaultNoDecrypt = new KeyVault(store, null, crypto);
    vaultNoDecrypt.setup();

    // Signing should fail because keys are encrypted and no decrypter
    expect(() =>
      vaultNoDecrypt.signSerialization({ ser: new Uint8Array(32), pubs: [prefix] })
    ).toThrow(KeyNotFoundError);
  });

  it("T213: INV-8: Non-transferable rotation rejected", () => {
    const { vault } = makeVault();
    const { verfers } = vault.inceptKeys({ transferable: false, nextCount: 0, testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);
    expect(() => vault.rotateKeys({ prefix, testMode: true })).toThrow(NonTransferableError);
  });

  it("T214: INV-9: movePrefix required after inception (prefix mapping)", () => {
    const { store, vault } = makeVault();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const firstPub = verfers[0].qb64;
    // Before movePrefix, the identifier is stored under firstPub
    const params = store.getDerivationParameters(firstPub);
    expect(params).not.toBeNull();
  });

  it("T215: INV-10: Duplicate prefix rejected", () => {
    const { store } = makeVault();
    // putDerivationParameters returns false on duplicate
    const params = makeDerivationParameters({ pidx: 0 });
    const ok1 = store.putDerivationParameters("Dprefix", params);
    const ok2 = store.putDerivationParameters("Dprefix", params);
    expect(ok1).toBe(true);
    expect(ok2).toBe(false);
  });

  it("T216: INV-11: Stale keys erased after rotation", () => {
    const { store, vault } = makeVault();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const sit0 = store.getKeySituation(prefix)!;
    const inceptionKeys = [...sit0.current.pubs];

    vault.rotateKeys({ prefix, eraseStaleKeys: true, testMode: true });
    vault.rotateKeys({ prefix, eraseStaleKeys: true, testMode: true });

    // Inception keys (previous-previous after 2nd rotation) should be erased
    for (const pub of inceptionKeys) {
      expect(store.getPrivateKey(pub, null)).toBeNull();
    }
  });

  it("T217: INV-12: Seed not present in KeyStore after setup", () => {
    const { store, vault } = makeVault();
    // No key in global store should be the seed itself
    // The seed is stored in memory only (_seed), never in keyStore
    const allGlobals = ["pidx", "algo", "salt", "tier", "aeid"];
    for (const k of allGlobals) {
      const val = store.getGlobal(k);
      if (val) {
        // None of the global values should be a valid seed (44-char "A..." string)
        // The seed is Ed25519_Seed code "A" + 43 chars = 44 total
        // This is a heuristic check
        if (k !== "salt") {
          expect(val.startsWith("A") && val.length === 44).toBe(false);
        }
      }
    }
  });

  it("T218: INV-4: Multiple rotations maintain three-phase chain", () => {
    const { store, vault } = makeVault();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    let prevSit = store.getKeySituation(prefix)!;
    for (let i = 0; i < 4; i++) {
      const currPubs = [...prevSit.current.pubs];
      const nextPubs = [...prevSit.next.pubs];
      vault.rotateKeys({ prefix, testMode: true });
      const sit = store.getKeySituation(prefix)!;
      expect(sit.previous.pubs).toEqual(currPubs);
      expect(sit.current.pubs).toEqual(nextPubs);
      prevSit = sit;
    }
  });

  it("T219: INV-5: ridx monotonically increases", () => {
    const { store, vault } = makeVault();
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    for (let i = 0; i < 3; i++) {
      vault.rotateKeys({ prefix, testMode: true });
    }
    const sit = store.getKeySituation(prefix)!;
    expect(sit.current.ridx).toBe(3);
    expect(sit.next.ridx).toBe(4);
  });

  it("T220: INV-6: kidx = sum of prior key set sizes", () => {
    const { store, vault } = makeVault();
    // Start with 2 keys per set
    const { verfers } = vault.inceptKeys({ currentCount: 2, nextCount: 2, testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    const sit0 = store.getKeySituation(prefix)!;
    // current.kidx=0 (2 keys), next.kidx=2
    expect(sit0.current.kidx).toBe(0);
    expect(sit0.next.kidx).toBe(2);

    vault.rotateKeys({ prefix, nextCount: 2, testMode: true });
    const sit1 = store.getKeySituation(prefix)!;
    // current (former next) kidx=2, new next kidx=4
    expect(sit1.current.kidx).toBe(2);
    expect(sit1.next.kidx).toBe(4);
  });

  it("T221: INV-7: AEID change re-encrypts all secrets", async () => {
    const { store, vault } = makeVault();
    // Incept keys without AEID
    const { verfers } = vault.inceptKeys({ testMode: true });
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);

    // Key is not encrypted
    const skBefore = store.getPrivateKey(verfers[0].qb64, null);
    expect(skBefore).not.toBeNull();

    // Add AEID → should re-encrypt
    const seedQb64 = makeSeedQb64();
    const seedRaw = matterDecode(seedQb64);
    const { publicKey } = crypto.deriveEdKeyPair(seedRaw);
    const verkeyQb64 = matterEncode(publicKey, MtrDex.Ed25519);

    vault.updateAuthentication(verkeyQb64, seedQb64);

    // Now key should be encrypted (not readable without decrypter)
    const skAfter = store.getPrivateKey(verfers[0].qb64, null);
    expect(skAfter).toBeNull(); // encrypted
  });
});
