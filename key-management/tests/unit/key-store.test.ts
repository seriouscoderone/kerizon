/**
 * T187–T206: KeyStore Compliance Tests
 */
import { describe, it, expect } from "vitest";
import { InMemoryKeyStore } from "../../src/memory/in-memory-key-store.js";
import { KeyStoreClosedError } from "../../src/errors.js";
import { makeDerivationParameters, makeKeySituation, makeKeySet, KeyAlgorithm, SecurityTier } from "../../src/types.js";
import { makeSigningKey } from "../../src/signing-key.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { SecretEncryptor } from "../../src/encryption/secret-encryptor.js";
import { SecretDecryptor } from "../../src/encryption/secret-decryptor.js";
import { MtrDex, matterEncode } from "../../src/cesr-helpers.js";

const crypto = new DefaultCryptographicSuite();

function makeTestSigner(transferable = true) {
  const raw = crypto.generateRandom(32);
  return makeSigningKey(raw, transferable);
}

describe("T187-T206: InMemoryKeyStore Compliance", () => {
  it("T187: open/close lifecycle", () => {
    const store = new InMemoryKeyStore();
    expect(store.isOpened()).toBe(false);
    store.open();
    expect(store.isOpened()).toBe(true);
    store.close();
    expect(store.isOpened()).toBe(false);
  });

  it("T188: Operations on closed store raise KeyStoreClosedError", () => {
    const store = new InMemoryKeyStore();
    expect(() => store.getGlobal("test")).toThrow(KeyStoreClosedError);
    expect(() => store.putGlobal("test", "val")).toThrow(KeyStoreClosedError);
  });

  it("T189: putGlobal/getGlobal round-trip", () => {
    const store = new InMemoryKeyStore();
    store.open();
    store.putGlobal("mykey", "myval");
    expect(store.getGlobal("mykey")).toBe("myval");
  });

  it("T190: pinGlobal overwrites existing value", () => {
    const store = new InMemoryKeyStore();
    store.open();
    store.putGlobal("k", "v1");
    store.pinGlobal("k", "v2");
    expect(store.getGlobal("k")).toBe("v2");
  });

  it("T191: putPrivateKey/getPrivateKey round-trip (unencrypted)", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const signer = makeTestSigner();
    store.putPrivateKey(signer.verfer.qb64, signer, null);
    const retrieved = store.getPrivateKey(signer.verfer.qb64, null);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.raw).toEqual(signer.raw);
  });

  it("T192: putPrivateKey/getPrivateKey round-trip (encrypted)", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const encSeedRaw = crypto.generateRandom(32);
    const { publicKey } = crypto.deriveEdKeyPair(encSeedRaw);
    const verkeyQb64 = matterEncode(publicKey, MtrDex.Ed25519);
    const seedQb64 = matterEncode(encSeedRaw, MtrDex.Ed25519_Seed);
    const enc = new SecretEncryptor({ verkey: verkeyQb64, crypto });
    const dec = new SecretDecryptor({ seed: seedQb64, crypto });

    const signer = makeTestSigner();
    store.putPrivateKey(signer.verfer.qb64, signer, enc);
    const retrieved = store.getPrivateKey(signer.verfer.qb64, dec);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.raw).toEqual(signer.raw);
  });

  it("T193: removePrivateKey deletes entry", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const signer = makeTestSigner();
    store.putPrivateKey(signer.verfer.qb64, signer, null);
    store.removePrivateKey(signer.verfer.qb64);
    expect(store.getPrivateKey(signer.verfer.qb64, null)).toBeNull();
  });

  it("T194: getPrivateKey returns null for missing key", () => {
    const store = new InMemoryKeyStore();
    store.open();
    expect(store.getPrivateKey("Dmissingkey123456789012345678901234567890ab", null)).toBeNull();
  });

  it("T195: putPrefixMapping/getPrefixMapping round-trip", () => {
    const store = new InMemoryKeyStore();
    store.open();
    store.putPrefixMapping("Dfirstkey123456789012345678901234567890abc", "Dprefix123456789012345678901234567890abcdef");
    const result = store.getPrefixMapping("Dfirstkey123456789012345678901234567890abc");
    expect(result).toBe("Dprefix123456789012345678901234567890abcdef");
  });

  it("T196: putPrefixMapping returns false on duplicate", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const ok1 = store.putPrefixMapping("Dkey1", "Dprefix1");
    const ok2 = store.putPrefixMapping("Dkey1", "Dprefix2");
    expect(ok1).toBe(true);
    expect(ok2).toBe(false);
  });

  it("T197: putDerivationParameters/getDerivationParameters round-trip", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const params = makeDerivationParameters({ pidx: 5 });
    store.putDerivationParameters("Dprefix", params);
    const retrieved = store.getDerivationParameters("Dprefix");
    expect(retrieved).not.toBeNull();
    expect(retrieved!.pidx).toBe(5);
  });

  it("T198: putKeySituation/getKeySituation round-trip", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const situation = makeKeySituation({
      current: makeKeySet({ pubs: ["Dkey1"], ridx: 0 }),
    });
    store.putKeySituation("Dprefix", situation);
    const retrieved = store.getKeySituation("Dprefix");
    expect(retrieved).not.toBeNull();
    expect(retrieved!.current.pubs).toEqual(["Dkey1"]);
  });

  it("T199: putPublicKeySet/getPublicKeySet round-trip", () => {
    const store = new InMemoryKeyStore();
    store.open();
    store.putPublicKeySet("Dprefix.0", { pubs: ["Dkey1", "Dkey2"] });
    const retrieved = store.getPublicKeySet("Dprefix.0");
    expect(retrieved).not.toBeNull();
    expect(retrieved!.pubs).toEqual(["Dkey1", "Dkey2"]);
  });

  it("T200: putSigningMembers/getSigningMembers round-trip", () => {
    const store = new InMemoryKeyStore();
    store.open();
    store.putSigningMembers("Dprefix", [{ prefix: "Dmember1", sequenceNumber: 0 }]);
    const retrieved = store.getSigningMembers("Dprefix");
    expect(retrieved).not.toBeNull();
    expect(retrieved![0].prefix).toBe("Dmember1");
  });

  it("T201: putRotatingMembers/getRotatingMembers round-trip", () => {
    const store = new InMemoryKeyStore();
    store.open();
    store.putRotatingMembers("Dprefix", [{ prefix: "Dmember1", sequenceNumber: 0 }]);
    const retrieved = store.getRotatingMembers("Dprefix");
    expect(retrieved).not.toBeNull();
    expect(retrieved![0].prefix).toBe("Dmember1");
  });

  it("T202: pinPrivateKey overwrites existing", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const signer1 = makeTestSigner();
    const signer2 = makeTestSigner();
    store.putPrivateKey(signer1.verfer.qb64, signer1, null);
    store.pinPrivateKey(signer1.verfer.qb64, signer2, null);
    const retrieved = store.getPrivateKey(signer1.verfer.qb64, null);
    expect(retrieved!.raw).toEqual(signer2.raw);
  });

  it("T203: removeDerivationParameters deletes entry", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const params = makeDerivationParameters({ pidx: 1 });
    store.putDerivationParameters("Dprefix", params);
    store.removeDerivationParameters("Dprefix");
    expect(store.getDerivationParameters("Dprefix")).toBeNull();
  });

  it("T204: pinDerivationParameters upserts", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const p1 = makeDerivationParameters({ pidx: 1 });
    const p2 = makeDerivationParameters({ pidx: 2 });
    store.putDerivationParameters("Dprefix", p1);
    store.pinDerivationParameters("Dprefix", p2);
    expect(store.getDerivationParameters("Dprefix")!.pidx).toBe(2);
  });

  it("T205: pinKeySituation upserts", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const s1 = makeKeySituation({ current: makeKeySet({ ridx: 0 }) });
    const s2 = makeKeySituation({ current: makeKeySet({ ridx: 1 }) });
    store.putKeySituation("Dprefix", s1);
    store.pinKeySituation("Dprefix", s2);
    expect(store.getKeySituation("Dprefix")!.current.ridx).toBe(1);
  });

  it("T206: Multiple concurrent prefixes isolated", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const p1 = makeDerivationParameters({ pidx: 1 });
    const p2 = makeDerivationParameters({ pidx: 2 });
    store.putDerivationParameters("Dprefix1", p1);
    store.putDerivationParameters("Dprefix2", p2);
    expect(store.getDerivationParameters("Dprefix1")!.pidx).toBe(1);
    expect(store.getDerivationParameters("Dprefix2")!.pidx).toBe(2);
  });
});
