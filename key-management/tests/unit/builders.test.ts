/**
 * T074–T091: Builder Tests
 */
import { describe, it, expect } from "vitest";
import { InceptionKeySetBuilder } from "../../src/builders/inception-keys.js";
import { RotationKeySetBuilder } from "../../src/builders/rotation-keys.js";
import { GroupKeySetBuilder } from "../../src/builders/group-keys.js";
import { KeyVault } from "../../src/key-vault.js";
import { InMemoryKeyStore } from "../../src/memory/in-memory-key-store.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { DerivationError, NonTransferableError, PrefixNotFoundError } from "../../src/errors.js";
import { makeDerivationParameters } from "../../src/types.js";
import { MtrDex } from "../../src/cesr-helpers.js";

function makeOpenVault(): { store: InMemoryKeyStore; vault: KeyVault } {
  const store = new InMemoryKeyStore();
  store.open();
  const vault = new KeyVault(store, null, new DefaultCryptographicSuite());
  vault.setup();
  return { store, vault };
}

describe("T074-T083: InceptionKeySetBuilder", () => {
  it("T074: InceptionKeySetBuilder default: 1 current key, 1 next key", () => {
    const { vault } = makeOpenVault();
    const { verfers, digers } = new InceptionKeySetBuilder().testMode(true).build(vault);
    expect(verfers.length).toBe(1);
    expect(digers.length).toBe(1);
  });

  it("T075: InceptionKeySetBuilder custom counts", () => {
    const { vault } = makeOpenVault();
    const { verfers, digers } = new InceptionKeySetBuilder()
      .currentCount(2)
      .nextCount(3)
      .testMode(true)
      .build(vault);
    expect(verfers.length).toBe(2);
    expect(digers.length).toBe(3);
  });

  it("T076: InceptionKeySetBuilder explicit codes override count", () => {
    const { vault } = makeOpenVault();
    const { verfers } = new InceptionKeySetBuilder()
      .currentCodes([MtrDex.Ed25519_Seed, MtrDex.Ed25519_Seed, MtrDex.Ed25519_Seed])
      .testMode(true)
      .build(vault);
    expect(verfers.length).toBe(3);
  });

  it("T077: InceptionKeySetBuilder rooted inherits vault defaults", () => {
    const { vault } = makeOpenVault();
    // rooted=true uses vault's stored salt/algorithm
    const { verfers } = new InceptionKeySetBuilder().rooted(true).testMode(true).build(vault);
    expect(verfers.length).toBe(1);
  });

  it("T078: InceptionKeySetBuilder non-rooted uses provided values", () => {
    const { vault } = makeOpenVault();
    const { verfers } = new InceptionKeySetBuilder()
      .rooted(false)
      .testMode(true)
      .build(vault);
    expect(verfers.length).toBe(1);
  });

  it("T079: InceptionKeySetBuilder non-transferable: nextCount=0 produces empty digers", () => {
    const { vault } = makeOpenVault();
    const { verfers, digers } = new InceptionKeySetBuilder()
      .transferable(false)
      .nextCount(0)
      .testMode(true)
      .build(vault);
    expect(verfers.length).toBe(1);
    expect(digers.length).toBe(0);
  });

  it("T080: InceptionKeySetBuilder rejects zero current count", () => {
    const { vault } = makeOpenVault();
    expect(() =>
      new InceptionKeySetBuilder().currentCount(0).testMode(true).build(vault)
    ).toThrow(DerivationError);
  });

  it("T081: InceptionKeySetBuilder rejects negative next count", () => {
    const { vault } = makeOpenVault();
    expect(() =>
      new InceptionKeySetBuilder().nextCount(-1).testMode(true).build(vault)
    ).toThrow(DerivationError);
  });

  it("T082: InceptionKeySetBuilder stores DerivationParameters in KeyStore", () => {
    const { store, vault } = makeOpenVault();
    const { verfers } = new InceptionKeySetBuilder().testMode(true).build(vault);
    const params = store.getDerivationParameters(verfers[0].qb64);
    expect(params).not.toBeNull();
    expect(params!.pidx).toBe(0);
  });

  it("T083: InceptionKeySetBuilder increments pidx", () => {
    const { store, vault } = makeOpenVault();
    new InceptionKeySetBuilder().testMode(true).build(vault);
    new InceptionKeySetBuilder().testMode(true).build(vault);
    const pidx = parseInt(store.getGlobal("pidx") ?? "0", 10);
    expect(pidx).toBe(2);
  });
});

describe("T084-T088: RotationKeySetBuilder", () => {
  it("T084: RotationKeySetBuilder advances three-phase state", () => {
    const { store, vault } = makeOpenVault();
    const { verfers: origVerfers } = new InceptionKeySetBuilder().testMode(true).build(vault);
    const prefix = origVerfers[0].qb64;
    vault.movePrefix(prefix, prefix); // same key as prefix

    const { verfers } = new RotationKeySetBuilder()
      .forIdentifier(prefix)
      .testMode(true)
      .build(vault);
    expect(verfers.length).toBe(1);
    // Rotated keys should differ from inception keys
    expect(verfers[0].qb64).not.toBe(origVerfers[0].qb64);
  });

  it("T085: RotationKeySetBuilder rejects absent prefix", () => {
    const { vault } = makeOpenVault();
    expect(() =>
      new RotationKeySetBuilder()
        .forIdentifier("Dnotexistent1234567890123456789012345678901")
        .testMode(true)
        .build(vault)
    ).toThrow(PrefixNotFoundError);
  });

  it("T086: RotationKeySetBuilder rejects non-transferable prefix", () => {
    const { vault } = makeOpenVault();
    const { verfers } = new InceptionKeySetBuilder()
      .transferable(false)
      .nextCount(0)
      .testMode(true)
      .build(vault);
    const prefix = verfers[0].qb64;
    vault.movePrefix(prefix, prefix);
    expect(() =>
      new RotationKeySetBuilder().forIdentifier(prefix).testMode(true).build(vault)
    ).toThrow(NonTransferableError);
  });

  it("T087: RotationKeySetBuilder eraseStaleKeys removes old private keys", () => {
    const { store, vault } = makeOpenVault();
    const { verfers: origVerfers } = new InceptionKeySetBuilder().testMode(true).build(vault);
    const prefix = origVerfers[0].qb64;
    vault.movePrefix(prefix, prefix);
    // First rotation: previous.pubs is empty, so no erasure happens yet
    new RotationKeySetBuilder().forIdentifier(prefix).eraseStaleKeys(true).testMode(true).build(vault);
    // Second rotation: old previous-previous (inception keys) should be erased
    new RotationKeySetBuilder().forIdentifier(prefix).eraseStaleKeys(true).testMode(true).build(vault);
    // The original inception keys (origVerfers) should now be erased
    const sk = store.getPrivateKey(origVerfers[0].qb64, null);
    expect(sk).toBeNull();
  });

  it("T088: RotationKeySetBuilder eraseStaleKeys=false preserves old keys", () => {
    const { store, vault } = makeOpenVault();
    const { verfers: origVerfers } = new InceptionKeySetBuilder().testMode(true).build(vault);
    const prefix = origVerfers[0].qb64;
    vault.movePrefix(prefix, prefix);
    new RotationKeySetBuilder().forIdentifier(prefix).eraseStaleKeys(false).testMode(true).build(vault);
    new RotationKeySetBuilder().forIdentifier(prefix).eraseStaleKeys(false).testMode(true).build(vault);
    // Original keys still exist
    const sk = store.getPrivateKey(origVerfers[0].qb64, null);
    expect(sk).not.toBeNull();
  });
});

describe("T089-T091: GroupKeySetBuilder", () => {
  it("T089: GroupKeySetBuilder assembles verfers from member key states", () => {
    const { vault: v1 } = makeOpenVault();
    const { vault: v2 } = makeOpenVault();
    const { verfers: v1Keys } = new InceptionKeySetBuilder().testMode(true).build(v1);
    const { verfers: v2Keys } = new InceptionKeySetBuilder().testMode(true).build(v2);

    const builder = new GroupKeySetBuilder()
      .withMemberKeyState(v1Keys[0].qb64, {
        prefix: v1Keys[0].qb64, sequenceNumber: 0, keys: [v1Keys[0].qb64], nextKeys: [],
      })
      .withMemberKeyState(v2Keys[0].qb64, {
        prefix: v2Keys[0].qb64, sequenceNumber: 0, keys: [v2Keys[0].qb64], nextKeys: [],
      })
      .addSigningMember(v1Keys[0].qb64, 0)
      .addSigningMember(v2Keys[0].qb64, 0)
      .signingThreshold("2");

    const { verfers } = builder.build();
    expect(verfers.length).toBe(2);
    expect(verfers[0].qb64).toBe(v1Keys[0].qb64);
    expect(verfers[1].qb64).toBe(v2Keys[0].qb64);
  });

  it("T090: GroupKeySetBuilder assembles digers from rotating members", () => {
    const { vault: v1 } = makeOpenVault();
    const { verfers: v1Keys, digers: v1Digers } = new InceptionKeySetBuilder()
      .testMode(true)
      .build(v1);

    const builder = new GroupKeySetBuilder()
      .withMemberKeyState(v1Keys[0].qb64, {
        prefix: v1Keys[0].qb64,
        sequenceNumber: 0,
        keys: [v1Keys[0].qb64],
        nextKeys: [v1Digers[0].qb64],
      })
      .addSigningMember(v1Keys[0].qb64, 0);

    const { digers } = builder.build();
    expect(digers.length).toBe(1);
    expect(digers[0].qb64).toBe(v1Digers[0].qb64);
  });

  it("T091: GroupKeySetBuilder builds without error when members have keys", () => {
    const { vault } = makeOpenVault();
    const { verfers, digers } = new InceptionKeySetBuilder().testMode(true).build(vault);

    const builder = new GroupKeySetBuilder()
      .withMemberKeyState(verfers[0].qb64, {
        prefix: verfers[0].qb64,
        sequenceNumber: 0,
        keys: [verfers[0].qb64],
        nextKeys: [digers[0].qb64],
      })
      .addSigningMember(verfers[0].qb64, 0);

    expect(() => builder.build()).not.toThrow();
  });
});
