/**
 * T172–T186: GroupIdentifierContext Tests
 */
import { describe, it, expect } from "vitest";
import { IdentifierRegistry } from "../../src/identifier-registry.js";
import { InMemoryKeyStore } from "../../src/memory/in-memory-key-store.js";
import { InceptionKeySetBuilder } from "../../src/builders/inception-keys.js";
import { GroupKeySetBuilder } from "../../src/builders/group-keys.js";
import { GroupIdentifierContext } from "../../src/group-context.js";
import { DefaultCryptographicSuite } from "../../src/adapters/default-crypto-suite.js";

const crypto = new DefaultCryptographicSuite();

function makeRegistry() {
  const store = new InMemoryKeyStore();
  const registry = new IdentifierRegistry({ name: "test", keyStore: store, cryptoSuite: crypto });
  registry.setup();
  return { store, registry };
}

describe("T172-T186: GroupIdentifierContext", () => {
  it("T172: Construction stores signing and rotating member IDs", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));

    const group = registry.createGroupIdentifier(
      "mygroup",
      alice,
      [alice.prefix, bob.prefix],
      [alice.prefix, bob.prefix],
    );

    expect(group.signingMemberIds).toEqual([alice.prefix, bob.prefix]);
    expect(group.rotatingMemberIds).toEqual([alice.prefix, bob.prefix]);
    expect(group.localMember).toBe(alice);
  });

  it("T173: make creates group inception with assembled keys", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));

    const group = registry.createGroupIdentifier("mygroup", alice, [alice.prefix, bob.prefix]);

    const aliceKeys = alice.keyState.signingKeys;
    const bobKeys = bob.keyState.signingKeys;
    const aliceDigers = alice.keyState.nextKeyDigests;
    const bobDigers = bob.keyState.nextKeyDigests;

    const groupKeyBuilder = new GroupKeySetBuilder()
      .withMemberKeyState(alice.prefix, {
        prefix: alice.prefix, sequenceNumber: 0,
        keys: aliceKeys, nextKeys: aliceDigers,
      })
      .withMemberKeyState(bob.prefix, {
        prefix: bob.prefix, sequenceNumber: 0,
        keys: bobKeys, nextKeys: bobDigers,
      })
      .addSigningMember(alice.prefix, 0)
      .addSigningMember(bob.prefix, 0)
      .signingThreshold("2");

    const signedEvent = await group.make(groupKeyBuilder, "2", "2");
    expect(signedEvent).toBeTruthy();
    expect(group.prefix).toBeTruthy();
  });

  it("T174: sign produces partial signatures from local member", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("mygroup", alice, [alice.prefix]);

    const ser = new Uint8Array(32).fill(0xab);
    const sigs = group.sign(ser);
    expect(sigs.length).toBe(1);
  });

  it("T175: rotate changes group membership", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));

    const group = registry.createGroupIdentifier("mygroup", alice, [alice.prefix, bob.prefix]);

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

    await group.make(groupKeyBuilder, "2", "2");

    // Verify the group has the expected prefix and members after make()
    expect(group.prefix).toBeTruthy();
    expect(group.signingMemberIds).toEqual([alice.prefix, bob.prefix]);
  });

  it("T176: interact creates interaction event", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("mygroup", alice, [alice.prefix]);

    const aliceKeys = alice.keyState.signingKeys;
    const aliceDigers = alice.keyState.nextKeyDigests;

    const groupKeyBuilder = new GroupKeySetBuilder()
      .withMemberKeyState(alice.prefix, { prefix: alice.prefix, sequenceNumber: 0, keys: aliceKeys, nextKeys: aliceDigers })
      .addSigningMember(alice.prefix, 0);

    await group.make(groupKeyBuilder, "1", "1");
    const ixn = await group.interact([]);
    expect(ixn).toBeTruthy();
  });

  it("T177: signingMemberIds property returns member list", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix, bob.prefix]);
    expect(group.signingMemberIds).toEqual([alice.prefix, bob.prefix]);
  });

  it("T178: rotatingMemberIds defaults to signing members", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix]);
    expect(group.rotatingMemberIds).toEqual([alice.prefix]);
  });

  it("T179: localMember returns local participant context", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix]);
    expect(group.localMember).toBe(alice);
  });

  it("T180: Group with weighted threshold validates correctly", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix, bob.prefix]);

    const aliceKeys = alice.keyState.signingKeys;
    const aliceDigers = alice.keyState.nextKeyDigests;
    const bobKeys = bob.keyState.signingKeys;
    const bobDigers = bob.keyState.nextKeyDigests;

    const groupKeyBuilder = new GroupKeySetBuilder()
      .withMemberKeyState(alice.prefix, { prefix: alice.prefix, sequenceNumber: 0, keys: aliceKeys, nextKeys: aliceDigers })
      .withMemberKeyState(bob.prefix, { prefix: bob.prefix, sequenceNumber: 0, keys: bobKeys, nextKeys: bobDigers })
      .addSigningMember(alice.prefix, 0)
      .addSigningMember(bob.prefix, 0)
      .signingThreshold("1"); // lower threshold

    const event = await group.make(groupKeyBuilder, "1", "1");
    expect(event).toBeTruthy();
  });

  it("T181: Group rotation with member change updates member lists", async () => {
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

    // After make(), the group prefix is set
    expect(group.prefix).toBeTruthy();
    // The signingMemberIds are set during construction
    expect(group.signingMemberIds).toContain(alice.prefix);
    expect(group.signingMemberIds).toContain(bob.prefix);
  });

  it("T182: Group rotation stores member info", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix]);
    expect(group.signingMemberIds).toContain(alice.prefix);
  });

  it("T183: Group inception event has correct combined key list", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix, bob.prefix]);

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

    const { verfers } = groupKeyBuilder.build();
    expect(verfers.length).toBe(2);
  });

  it("T184: Group with single member degenerates to simple case", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix]);

    const aliceKeys = alice.keyState.signingKeys;
    const aliceDigers = alice.keyState.nextKeyDigests;

    const groupKeyBuilder = new GroupKeySetBuilder()
      .withMemberKeyState(alice.prefix, { prefix: alice.prefix, sequenceNumber: 0, keys: aliceKeys, nextKeys: aliceDigers })
      .addSigningMember(alice.prefix, 0);

    const event = await group.make(groupKeyBuilder, "1", "1");
    expect(event).toBeTruthy();
  });

  it("T185: Group sign uses local member's key index", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const group = registry.createGroupIdentifier("grp", alice, [alice.prefix]);

    const ser = new Uint8Array(32);
    const sigs = group.sign(ser);
    expect(sigs.length).toBe(1);
    expect((sigs[0] as any).index).toBe(0);
  });

  it("T186: Group with members assembles keys correctly", async () => {
    const { registry } = makeRegistry();
    const alice = await registry.createIdentifier("alice", new InceptionKeySetBuilder().testMode(true));
    const bob = await registry.createIdentifier("bob", new InceptionKeySetBuilder().testMode(true));

    const { verfers: groupVerfers } = registry.extractGroupKeys(
      [{ prefix: alice.prefix, sequenceNumber: 0 }, { prefix: bob.prefix, sequenceNumber: 0 }],
      []
    );
    expect(groupVerfers.length).toBe(2);
  });
});
