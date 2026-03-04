import { describe, it, expect } from "vitest";
import { MockKeyStateResolver } from "../../src/memory/MockKeyStateResolver.js";
import { toAID } from "../../src/types/AID.js";
import { dummyAID, makeKeyState, generateKeyPair } from "../helpers.js";

const alice = dummyAID("Alice");
const bob = dummyAID("Bob");

describe("MockKeyStateResolver", () => {
  it("returns null for unknown AID", async () => {
    const resolver = new MockKeyStateResolver();
    expect(await resolver.resolve(alice)).toBeNull();
  });

  it("returns null from refresh for unknown AID", async () => {
    const resolver = new MockKeyStateResolver();
    expect(await resolver.refresh(alice)).toBeNull();
  });

  it("resolves a seeded key state", async () => {
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    const seed = new Map([[alice, ks]]);
    const resolver = new MockKeyStateResolver(seed);
    const result = await resolver.resolve(alice);
    expect(result).toStrictEqual(ks);
  });

  it("add() makes a new AID resolvable", async () => {
    const resolver = new MockKeyStateResolver();
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    resolver.add(alice, ks);
    expect(await resolver.resolve(alice)).toStrictEqual(ks);
  });

  it("remove() makes an AID unresolvable", async () => {
    const kp = await generateKeyPair();
    const resolver = new MockKeyStateResolver(
      new Map([[alice, makeKeyState(kp.verferQb64)]]),
    );
    resolver.remove(alice);
    expect(await resolver.resolve(alice)).toBeNull();
  });

  it("refresh() returns the same value as resolve()", async () => {
    const kp = await generateKeyPair();
    const ks = makeKeyState(kp.verferQb64);
    const resolver = new MockKeyStateResolver(new Map([[alice, ks]]));
    expect(await resolver.refresh(alice)).toStrictEqual(
      await resolver.resolve(alice),
    );
  });
});
