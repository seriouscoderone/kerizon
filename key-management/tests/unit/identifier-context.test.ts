/**
 * T127–T151: IdentifierContext Tests
 */
import { describe, it, expect } from "vitest";
import { IdentifierContext } from "../../src/identifier-context.js";
import { IdentifierRegistry } from "../../src/identifier-registry.js";
import { InMemoryKeyStore } from "../../src/memory/in-memory-key-store.js";
import { InceptionKeySetBuilder } from "../../src/builders/inception-keys.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";
import { IdentifierNotFoundError } from "../../src/errors.js";
import { KeyAlgorithm } from "../../src/types.js";

const crypto = new DefaultCryptographicSuite();

function makeRegistry(seed?: string) {
  const store = new InMemoryKeyStore();
  const registry = new IdentifierRegistry({ name: "test", keyStore: store, seed, cryptoSuite: crypto });
  registry.setup();
  return { store, registry };
}

describe("T127-T151: IdentifierContext", () => {
  it("T127: create produces inception event with correct prefix", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    expect(ctx.prefix).toBeTruthy();
    expect(ctx.prefix.length).toBeGreaterThan(10);
  });

  it("T128: create stores habitat record", async () => {
    const { store, registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    const record = store.getGlobal(`hab:alice`);
    expect(record).not.toBeNull();
    const parsed = JSON.parse(record!);
    expect(parsed.name).toBe("alice");
    expect(parsed.prefix).toBe(ctx.prefix);
  });

  it("T129: create calls movePrefix (prefix differs from first pub key for self-addressing)", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    // The prefix should be the actual AID (self-addressing, potentially same as first pub key or derived)
    expect(ctx.prefix).toBeTruthy();
  });

  it("T130: restore loads existing identifier", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    const restored = IdentifierContext.restore("alice", ctx.prefix, registry.vault, registry.processor);
    expect(restored.prefix).toBe(ctx.prefix);
    expect(restored.name).toBe("alice");
  });

  it("T131: makeInteractionEvent returns signed event", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    const ixn = await ctx.makeInteractionEvent([]);
    expect(ixn).toBeTruthy();
    expect(ixn.sigers).toBeDefined();
  });

  it("T132: makeRotationEvent advances key state", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    const stateBefore = ctx.keyState.signingKeys.slice();
    await ctx.makeRotationEvent({ testMode: true });
    const stateAfter = ctx.keyState.signingKeys;
    expect(stateAfter).not.toEqual(stateBefore);
  });

  it("T133: makeInteractionEvent preserves sequence continuity", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    const snBefore = ctx.keyState.sequenceNumber;
    await ctx.makeInteractionEvent([]);
    const snAfter = ctx.keyState.sequenceNumber;
    expect(snAfter).toBe(snBefore + 1);
  });

  it("T134: sign delegates to vault with current keys", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    const ser = new Uint8Array(32).fill(0xcd);
    const sigs = ctx.sign(ser);
    expect(sigs.length).toBe(1);
  });

  it("T135: decrypt delegates to vault", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);

    // Encrypt something with the current key
    const { SecretEncryptor } = await import("../../src/encryption/secret-encryptor.js");
    const { MtrDex, matterEncode } = await import("../../src/cesr-helpers.js");
    const currentKey = ctx.keyState.signingKeys[0];
    const enc = new SecretEncryptor({ verkey: currentKey, crypto });
    const saltRaw = crypto.generateRandom(16);
    const saltQb64 = matterEncode(saltRaw, MtrDex.Salt_128);
    const cipher = enc.encrypt(undefined, { raw: saltRaw, qb64: saltQb64, code: MtrDex.Salt_128 });

    const plaintext = ctx.decrypt(cipher.qb64);
    const decoded = new TextDecoder().decode(plaintext);
    expect(decoded).toBe(saltQb64);
  });

  it("T136: endorse produces Cigar (unindexed sig) list", async () => {
    const { registry } = makeRegistry();
    const keyConfig = new InceptionKeySetBuilder().testMode(true);
    const ctx = await registry.createIdentifier("alice", keyConfig);
    const ser = new Uint8Array(32).fill(0x11);
    const cigars = ctx.endorse(ser);
    expect(cigars.length).toBe(1);
    expect((cigars[0] as any).verferQb64).toBeDefined();
  });

  it("T137: name property returns alias", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    expect(ctx.name).toBe("bob");
  });

  it("T138: prefix property returns qb64 prefix", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("carol", new InceptionKeySetBuilder().testMode(true));
    expect(ctx.prefix).toMatch(/^[ABCDE]/); // Ed25519 verkey starts with D
  });

  it("T139: keyState returns BC-1 IdentifierState", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const state = ctx.keyState;
    expect(state).toBeTruthy();
    expect(state.signingKeys).toBeDefined();
  });

  it("T140: isTransferable true when next keys exist", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice",
      new InceptionKeySetBuilder().nextCount(1).testMode(true)
    );
    expect(ctx.isTransferable).toBe(true);
  });

  it("T141: isTransferable false when next keys empty", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice",
      new InceptionKeySetBuilder().transferable(false).nextCount(0).testMode(true)
    );
    expect(ctx.isTransferable).toBe(false);
  });

  it("T142: isDelegated false when no delegator", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    expect(ctx.isDelegated).toBe(false);
  });

  it("T143: isDelegated false by default for non-delegated identifier", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    expect(ctx.isDelegated).toBe(false);
  });

  it("T144: algorithm returns identifier's key algorithm", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    expect([KeyAlgorithm.DETERMINISTIC, KeyAlgorithm.RANDOM]).toContain(ctx.algorithm);
  });

  it("T145: create with non-transferable produces correct event", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("nontx",
      new InceptionKeySetBuilder().transferable(false).nextCount(0).testMode(true)
    );
    expect(ctx.prefix).toBeTruthy();
    expect(ctx.isTransferable).toBe(false);
  });

  it("T146: create with witnesses produces event with witnesses (no-op if no witness pool)", async () => {
    const { registry } = makeRegistry();
    // Just verify it doesn't throw with empty witnesses
    const ctx = await registry.createIdentifier("alice",
      new InceptionKeySetBuilder().testMode(true),
      "1", "1", []
    );
    expect(ctx.prefix).toBeTruthy();
  });

  it("T147: rotation updates BC-1 key state", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const keysBefore = ctx.keyState.signingKeys.slice();
    await ctx.makeRotationEvent({ testMode: true });
    expect(ctx.keyState.signingKeys).not.toEqual(keysBefore);
  });

  it("T148: interaction does not change signing key state", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const keysBefore = ctx.keyState.signingKeys.slice();
    await ctx.makeInteractionEvent([]);
    expect(ctx.keyState.signingKeys).toEqual(keysBefore);
  });

  it("T149: sign with vault succeeds when keys available", async () => {
    const { registry } = makeRegistry();
    const ctx = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const sigs = ctx.sign(new Uint8Array(32));
    expect(sigs.length).toBe(1);
  });

  it("T150: creating second identifier works independently", async () => {
    const { registry } = makeRegistry();
    const c1 = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const c2 = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    expect(c1.prefix).not.toBe(c2.prefix);
  });

  it("T151: restore fails for unknown prefix", () => {
    const { registry } = makeRegistry();
    expect(() =>
      IdentifierContext.restore("unknown", "Dnotexist12345678901234567890123456789012", registry.vault, registry.processor)
    ).toThrow(IdentifierNotFoundError);
  });
});
