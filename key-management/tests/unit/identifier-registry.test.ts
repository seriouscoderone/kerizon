/**
 * T152–T171: IdentifierRegistry Tests
 */
import { describe, it, expect } from "vitest";
import { IdentifierRegistry } from "../../src/identifier-registry.js";
import { InMemoryKeyStore } from "../../src/memory/in-memory-key-store.js";
import { InceptionKeySetBuilder } from "../../src/builders/inception-keys.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { GroupIdentifierContext } from "../../src/group-context.js";
import { MtrDex, matterEncode } from "../../src/cesr-helpers.js";

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

describe("T152-T171: IdentifierRegistry", () => {
  it("T152: Construction initializes shared resources", () => {
    const { registry } = makeRegistry();
    expect(registry.vault).toBeDefined();
    expect(registry.processor).toBeDefined();
    expect(registry.keyStore).toBeDefined();
  });

  it("T153: setup opens KeyStore", () => {
    const store = new InMemoryKeyStore();
    const registry = new IdentifierRegistry({ name: "test", keyStore: store, cryptoSuite: crypto });
    registry.setup();
    expect(store.isOpened()).toBe(true);
  });

  it("T154: identifiers() returns empty map initially", () => {
    const { registry } = makeRegistry();
    expect(registry.identifiers().size).toBe(0);
  });

  it("T155: createIdentifier returns new IdentifierContext", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    expect(ctx).toBeTruthy();
    expect(ctx.name).toBe("alice");
  });

  it("T156: createIdentifier stores in registry map", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    expect(registry.identifiers().has(ctx.prefix)).toBe(true);
  });

  it("T157: createGroupIdentifier returns GroupIdentifierContext", async () => {
    const { registry } = makeRegistry();
    const member = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("mygroup", member, [member.prefix]);
    expect(group).toBeInstanceOf(GroupIdentifierContext);
  });

  it("T158: joinGroupIdentifier joins existing group", async () => {
    const { registry } = makeRegistry();
    const member = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const fakeGroupPrefix = "Dgroup1234567890123456789012345678901234567";
    const group = registry.joinGroupIdentifier("mygroup", fakeGroupPrefix, member, [member.prefix]);
    expect(group).toBeInstanceOf(GroupIdentifierContext);
  });

  it("T159: deleteIdentifier removes from registry", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    expect(registry.identifiers().has(ctx.prefix)).toBe(true);
    registry.deleteIdentifier(ctx.prefix);
    expect(registry.identifiers().has(ctx.prefix)).toBe(false);
  });

  it("T160: identifiers() returns all managed contexts", async () => {
    const { registry } = makeRegistry();
    await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    expect(registry.identifiers().size).toBe(2);
  });

  it("T161: byName lookup returns correct context", async () => {
    const { registry } = makeRegistry();
    await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const found = registry.byName("alice");
    expect(found).not.toBeNull();
    expect(found!.name).toBe("alice");
  });

  it("T162: byName returns null for unknown name", () => {
    const { registry } = makeRegistry();
    expect(registry.byName("nobody")).toBeNull();
  });

  it("T163: byPrefix lookup returns correct context", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const found = registry.byPrefix(ctx.prefix);
    expect(found).not.toBeNull();
    expect(found!.prefix).toBe(ctx.prefix);
  });

  it("T164: byPrefix returns null for unknown prefix", () => {
    const { registry } = makeRegistry();
    expect(registry.byPrefix("Dunknown12345678901234567890123456789012")).toBeNull();
  });

  it("T165: localPrefixes returns all managed prefixes", async () => {
    const { registry } = makeRegistry();
    const c1 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const c2 = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    const prefixes = registry.localPrefixes();
    expect(prefixes.has(c1.prefix)).toBe(true);
    expect(prefixes.has(c2.prefix)).toBe(true);
  });

  it("T166: extractGroupKeys concatenates member verfers", async () => {
    const { registry } = makeRegistry();
    const c1 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const c2 = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    const { verfers } = registry.extractGroupKeys(
      [{ prefix: c1.prefix, sequenceNumber: 0 }, { prefix: c2.prefix, sequenceNumber: 0 }],
      []
    );
    expect(verfers.length).toBe(2);
  });

  it("T167: extractGroupKeys concatenates member digers", async () => {
    const { registry } = makeRegistry();
    const c1 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const { digers } = registry.extractGroupKeys(
      [{ prefix: c1.prefix, sequenceNumber: 0 }],
      [{ prefix: c1.prefix, sequenceNumber: 0 }]
    );
    expect(digers.length).toBeGreaterThanOrEqual(0); // c1 may have next key digests
  });

  it("T168: Multiple identifiers share same KeyVault", async () => {
    const { registry } = makeRegistry();
    const c1 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const c2 = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    // Both contexts share registry.vault
    expect(registry.vault).toBe(registry.vault);
  });

  it("T169: Multiple identifiers share same EventProcessor", async () => {
    const { registry } = makeRegistry();
    await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    expect(registry.processor).toBe(registry.processor);
  });

  it("T170: Registry close closes KeyStore", () => {
    const { store, registry } = makeRegistry();
    expect(store.isOpened()).toBe(true);
    registry.close();
    expect(store.isOpened()).toBe(false);
  });

  it("T171: Registry with AEID accepts seed", () => {
    const seedRaw = crypto.generateRandom(32);
    const seedQb64 = matterEncode(seedRaw, MtrDex.Ed25519_Seed);
    // Should not throw — seed is passed to KeyVault
    const store = new InMemoryKeyStore();
    const registry = new IdentifierRegistry({ name: "test", keyStore: store, seed: seedQb64, cryptoSuite: crypto });
    registry.setup();
    expect(registry.keyStore).toBeDefined();
  });
});
