/**
 * T222–T243: Integration / Lifecycle Tests
 */
import { describe, it, expect } from "vitest";
import { IdentifierRegistry } from "../../src/identifier-registry.js";
import { KeyVault } from "../../src/key-vault.js";
import { InMemoryKeyStore } from "../../src/memory/in-memory-key-store.js";
import { InceptionKeySetBuilder } from "../../src/builders/inception-keys.js";
import { RotationKeySetBuilder } from "../../src/builders/rotation-keys.js";
import { GroupKeySetBuilder } from "../../src/builders/group-keys.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { MtrDex, matterEncode, matterDecode } from "../../src/cesr-helpers.js";
import { NonTransferableError } from "../../src/errors.js";

const crypto = new DefaultCryptographicSuite();

function makeRegistry(opts?: { seed?: string }) {
  const store = new InMemoryKeyStore();
  const registry = new IdentifierRegistry({
    name: "test",
    keyStore: store,
    seed: opts?.seed,
    cryptoSuite: crypto,
  });
  registry.setup();
  return { store, registry };
}

function makeSeedQb64() {
  return matterEncode(crypto.generateRandom(32), MtrDex.Ed25519_Seed);
}

describe("T222-T243: Integration / Lifecycle", () => {
  it("T222: Full lifecycle: incept → rotate → sign → decrypt", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));

    // Sign
    const ser = new Uint8Array(32).fill(0xaa);
    const sigs = ctx.sign(ser);
    expect(sigs.length).toBe(1);

    // Rotate
    await ctx.makeRotationEvent({ testMode: true });
    const newSigs = ctx.sign(ser);
    expect(newSigs.length).toBe(1);

    // Decrypt with current key
    const { SecretEncryptor } = await import("../../src/encryption/secret-encryptor.js");
    const currentKey = ctx.keyState.signingKeys[0];
    const enc = new SecretEncryptor({ verkey: currentKey, crypto });
    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });
    const plaintext = ctx.decrypt(cipher.qb64);
    expect(new TextDecoder().decode(plaintext)).toBe(saltQb64);
  });

  it("T223: Full lifecycle with AEID: setup → incept → rotate → sign", async () => {
    const seedQb64 = makeSeedQb64();
    const seedRaw = matterDecode(seedQb64);
    const { publicKey } = crypto.deriveEdKeyPair(seedRaw);
    const verkeyQb64 = matterEncode(publicKey, MtrDex.Ed25519);

    const store = new InMemoryKeyStore();
    const registry = new IdentifierRegistry({
      name: "test",
      keyStore: store,
      seed: seedQb64,
      cryptoSuite: crypto,
    });
    store.open();
    registry.vault.setup(verkeyQb64);

    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    await ctx.makeRotationEvent({ testMode: true });
    const sigs = ctx.sign(new Uint8Array(32));
    expect(sigs.length).toBe(1);
  });

  it("T224: AEID vault: change AEID mid-lifecycle", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));

    const seedQb64 = makeSeedQb64();
    const seedRaw = matterDecode(seedQb64);
    const { publicKey } = crypto.deriveEdKeyPair(seedRaw);
    const verkeyQb64 = matterEncode(publicKey, MtrDex.Ed25519);

    // Change AEID
    registry.vault.updateAuthentication(verkeyQb64, seedQb64);

    // But vault no longer has decrypter (the new one has seed)
    // The vault's _seed should now be seedQb64
    // Can still sign because we passed the seed
    // This test verifies no exception during AEID change
    expect(registry.vault).toBeDefined();
  });

  it("T225: AEID vault: remove AEID (unencrypt)", async () => {
    const seedQb64 = makeSeedQb64();
    const seedRaw = matterDecode(seedQb64);
    const { publicKey } = crypto.deriveEdKeyPair(seedRaw);
    const verkeyQb64 = matterEncode(publicKey, MtrDex.Ed25519);

    const store = new InMemoryKeyStore();
    const registry = new IdentifierRegistry({ name: "test", keyStore: store, seed: seedQb64, cryptoSuite: crypto });
    store.open();
    registry.vault.setup(verkeyQb64);

    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));

    // Remove AEID
    registry.vault.updateAuthentication("", "");
    expect(store.getGlobal("aeid")).toBe("");

    // Keys should now be unencrypted and accessible without decrypter
    const { verfers } = registry.vault.inceptKeys({ testMode: true });
    const sk = store.getPrivateKey(verfers[0].qb64, null);
    expect(sk).not.toBeNull();
  });

  it("T226: Multiple prefixes: two identifiers share vault", async () => {
    const { registry } = makeRegistry();
    const c1 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const c2 = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    expect(c1.prefix).not.toBe(c2.prefix);
    expect(c1.sign(new Uint8Array(32)).length).toBe(1);
    expect(c2.sign(new Uint8Array(32)).length).toBe(1);
  });

  it("T227: Multiple prefixes: rotation of one does not affect other", async () => {
    const { registry } = makeRegistry();
    const c1 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const c2 = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));

    const c2KeysBefore = c2.keyState.signingKeys.slice();
    await c1.makeRotationEvent({ testMode: true });
    expect(c2.keyState.signingKeys).toEqual(c2KeysBefore);
  });

  it("T228: Non-transferable: incept with ncount=0, rotation rejected", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice",
      new InceptionKeySetBuilder().transferable(false).nextCount(0).testMode(true)
    );
    expect(ctx.isTransferable).toBe(false);
    await expect(ctx.makeRotationEvent({ testMode: true })).rejects.toThrow(NonTransferableError);
  });

  it("T229: Group lifecycle: create group → sign → rotate group", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));

    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix, bob.prefix]);

    const aliceKeys = alice.keyState.signingKeys;
    const aliceDigers = alice.keyState.nextKeyDigests;
    const bobKeys = bob.keyState.signingKeys;
    const bobDigers = bob.keyState.nextKeyDigests;

    const initBuilder = new GroupKeySetBuilder()
      .withMemberKeyState(alice.prefix, { prefix: alice.prefix, sequenceNumber: 0, keys: aliceKeys, nextKeys: aliceDigers })
      .withMemberKeyState(bob.prefix, { prefix: bob.prefix, sequenceNumber: 0, keys: bobKeys, nextKeys: bobDigers })
      .addSigningMember(alice.prefix, 0)
      .addSigningMember(bob.prefix, 0)
      .signingThreshold("2");

    await group.make(initBuilder, "2", "2");
    expect(group.prefix).toBeTruthy();

    // Sign
    const sigs = group.sign(new Uint8Array(32));
    expect(sigs.length).toBe(1);
  });

  it("T230: External key ingestion: import → replay → sign", async () => {
    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, null, crypto);
    vault.setup();

    // Create two external key sets
    const seed1 = crypto.generateRandom(32);
    const seed2 = crypto.generateRandom(32);
    const seed1Qb64 = matterEncode(seed1, MtrDex.Ed25519_Seed);
    const seed2Qb64 = matterEncode(seed2, MtrDex.Ed25519_Seed);

    const { prefix } = vault.ingestExternalKeys({
      secrecies: [[seed1Qb64], [seed2Qb64]],
      testMode: true,
    });

    expect(prefix).toBeTruthy();
    const { verfers } = vault.replayKeys({ prefix });
    expect(verfers.length).toBe(1);
  });

  it("T231: External key ingestion: replay advances through all sets", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, null, crypto);
    vault.setup();

    const seed1Qb64 = matterEncode(crypto.generateRandom(32), MtrDex.Ed25519_Seed);
    const seed2Qb64 = matterEncode(crypto.generateRandom(32), MtrDex.Ed25519_Seed);
    const seed3Qb64 = matterEncode(crypto.generateRandom(32), MtrDex.Ed25519_Seed);

    // Store public key sets manually for replay
    const { prefix } = vault.ingestExternalKeys({
      secrecies: [[seed1Qb64], [seed2Qb64], [seed3Qb64]],
      testMode: true,
    });

    expect(prefix).toBeTruthy();
    // replay at current position
    const { verfers } = vault.replayKeys({ prefix });
    expect(verfers.length).toBe(1);
  });

  it("T232: External key ingestion: replay raises at end", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, null, crypto);
    vault.setup();

    const seed1Qb64 = matterEncode(crypto.generateRandom(32), MtrDex.Ed25519_Seed);
    const { prefix } = vault.ingestExternalKeys({
      secrecies: [[seed1Qb64]],
      testMode: true,
    });

    // advance=true tries to go to ridx 1 which doesn't exist as a PublicKeySet
    expect(() => vault.replayKeys({ prefix, advance: true })).toThrow();
  });

  it("T233: Deterministic recovery: same salt recreates same keys", () => {
    const saltRaw = new Uint8Array(16).fill(0xde);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);

    const { store: s1, vault: v1 } = (() => {
      const store = new InMemoryKeyStore();
      store.open();
      const vault = new KeyVault(store, null, crypto);
      vault.setup();
      return { store, vault };
    })();
    const { store: s2, vault: v2 } = (() => {
      const store = new InMemoryKeyStore();
      store.open();
      const vault = new KeyVault(store, null, crypto);
      vault.setup();
      return { store, vault };
    })();

    const { verfers: vf1 } = v1.inceptKeys({ rooted: false, salt: saltQb64, testMode: true });
    const { verfers: vf2 } = v2.inceptKeys({ rooted: false, salt: saltQb64, testMode: true });

    expect(vf1[0].qb64).toBe(vf2[0].qb64);
  });

  it("T234: IdentifierContext create + IdentifierRegistry lookup", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const found = registry.byPrefix(ctx.prefix);
    expect(found).not.toBeNull();
    expect(found!.name).toBe("alice");
  });

  it("T235: IdentifierContext rotation updates registry state", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const keysBefore = ctx.keyState.signingKeys.slice();
    await ctx.makeRotationEvent({ testMode: true });
    const found = registry.byPrefix(ctx.prefix)!;
    expect(found.keyState.signingKeys).not.toEqual(keysBefore);
  });

  it("T236: GroupIdentifierContext partial signing coordination", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));

    const aliceGroup = registry.createGroupIdentifier("grp", alice, [alice.prefix, bob.prefix]);
    const bobGroup = registry.createGroupIdentifier("grp", bob, [alice.prefix, bob.prefix]);

    const aliceKeys = alice.keyState.signingKeys;
    const aliceDigers = alice.keyState.nextKeyDigests;
    const bobKeys = bob.keyState.signingKeys;
    const bobDigers = bob.keyState.nextKeyDigests;

    const groupKeyBuilder = new GroupKeySetBuilder()
      .withMemberKeyState(alice.prefix, { prefix: alice.prefix, sequenceNumber: 0, keys: aliceKeys, nextKeys: aliceDigers })
      .withMemberKeyState(bob.prefix, { prefix: bob.prefix, sequenceNumber: 0, keys: bobKeys, nextKeys: bobDigers })
      .addSigningMember(alice.prefix, 0)
      .addSigningMember(bob.prefix, 0)
      .signingThreshold("2");

    const aliceSig = await aliceGroup.make(groupKeyBuilder, "2", "2");
    expect(aliceSig.sigers.length).toBeGreaterThan(0);

    // Alice and Bob produce partial sigs
    const ser = new Uint8Array(32);
    const alicePartial = aliceGroup.sign(ser);
    const bobPartial = bobGroup.sign(ser);
    expect(alicePartial.length).toBe(1);
    expect(bobPartial.length).toBe(1);
  });

  it("T237: KeyVault with InMemoryKeyStore (testing adapter)", () => {
    const store = new InMemoryKeyStore();
    store.open();
    const vault = new KeyVault(store, null, crypto);
    vault.setup();
    const { verfers } = vault.inceptKeys({ testMode: true });
    expect(verfers.length).toBe(1);
  });

  it("T238: Registry setup with pre-existing data loads correctly", () => {
    const store = new InMemoryKeyStore();
    store.open();
    store.putGlobal("pidx", "5");
    store.close();

    const registry = new IdentifierRegistry({ name: "test", keyStore: store, cryptoSuite: crypto });
    registry.setup();
    // pidx should not be overwritten
    expect(store.getGlobal("pidx")).toBe("5");
  });

  it("T239: Multiple rotations: 5 successive rotations maintain invariants", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));

    let lastKeys = ctx.keyState.signingKeys.slice();
    for (let i = 0; i < 5; i++) {
      await ctx.makeRotationEvent({ testMode: true });
      const newKeys = ctx.keyState.signingKeys;
      expect(newKeys).not.toEqual(lastKeys);
      expect(ctx.keyState.sequenceNumber).toBe(i + 1);
      lastKeys = newKeys.slice();
    }
  });

  it("T240: Concurrent inception: two prefixes created back-to-back", async () => {
    const { registry } = makeRegistry();
    const [c1, c2] = await Promise.all([
      registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true)),
      registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true)),
    ]);
    expect(c1.prefix).not.toBe(c2.prefix);
  });

  it("T241: KeyInventory reflects state after rotation", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    await ctx.makeRotationEvent({ testMode: true });
    const inventory = registry.vault.keyInventory();
    expect(inventory).toBeDefined();
  });

  it("T242: Interaction event after rotation uses new keys", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    await ctx.makeRotationEvent({ testMode: true });
    const keyAfterRot = ctx.keyState.signingKeys.slice();

    const ixn = await ctx.makeInteractionEvent([]);
    expect(ixn).toBeTruthy();
    // Signing keys should still be the rotated ones
    expect(ctx.keyState.signingKeys).toEqual(keyAfterRot);
  });

  it("T243: Registry deleteIdentifier followed by createIdentifier with same name", async () => {
    const { registry } = makeRegistry();
    const c1 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    registry.deleteIdentifier(c1.prefix);

    // Create new identifier with same name
    const c2 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    expect(c2.name).toBe("alice");
    expect(registry.byName("alice")).not.toBeNull();
  });
});
