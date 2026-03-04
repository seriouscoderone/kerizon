import { describe, it, expect, beforeEach } from "vitest";
import { MemoryMailboxStore } from "../src/memory/MemoryMailboxStore.js";
import { MockKeyStateResolver } from "../src/memory/MockKeyStateResolver.js";
import { MailboxIngress } from "../src/services/MailboxIngress.js";
import { MailboxEgress } from "../src/services/MailboxEgress.js";
import { MailboxProvisioner } from "../src/services/MailboxProvisioner.js";
import { generateNonce } from "../src/core/ChallengeResponse.js";
import { toAID } from "../src/types/AID.js";
import type { EgressEvent } from "../src/types/results.js";
import {
  generateKeyPair,
  signMessage,
  encodeEd25519IndexedSig,
  makeKeyState,
  makeKeriJson,
  dummyAID,
} from "./helpers.js";

/**
 * Integration scenario:
 *   provision → submit → poll → receive
 */
describe("Full mailbox flow (no sender auth)", () => {
  const mailboxAid = dummyAID("Mailbox");
  const alice = dummyAID("Alice");

  let store: MemoryMailboxStore;
  let resolver: MockKeyStateResolver;
  let ingress: MailboxIngress;
  let egress: MailboxEgress;
  let provisioner: MailboxProvisioner;

  beforeEach(() => {
    store = new MemoryMailboxStore();
    resolver = new MockKeyStateResolver();
    ingress = new MailboxIngress({ store, resolver });
    egress = new MailboxEgress({ store, resolver });
    provisioner = new MailboxProvisioner({ store, resolver, mailboxAid });
  });

  it("submit fails if recipient is not provisioned", async () => {
    await expect(
      ingress.submit({
        sender: dummyAID("Bob"),
        recipient: alice,
        topic: "notice",
        payload: new Uint8Array([1]),
      }),
    ).rejects.toThrow(/not provisioned/i);
  });

  it("provision → submit → poll round-trip", async () => {
    // Provision alice
    await store.provision(alice);

    // Submit two messages
    const p1 = new TextEncoder().encode("hello");
    const p2 = new TextEncoder().encode("world");
    const sender = dummyAID("Bob");

    const r1 = await ingress.submit({
      sender,
      recipient: alice,
      topic: "notice",
      payload: p1,
    });
    const r2 = await ingress.submit({
      sender,
      recipient: alice,
      topic: "notice",
      payload: p2,
    });

    expect(r1.ordinal).toBe(0n);
    expect(r2.ordinal).toBe(1n);
    expect(r1.digest).toMatch(/^[0-9a-f]{64}$/);

    // Poll from the beginning
    const events: EgressEvent[] = [];
    for await (const ev of egress.poll({
      recipient: alice,
      cursors: new Map([["notice", 0n]]),
    })) {
      events.push(ev);
    }

    expect(events).toHaveLength(2);
    expect(events[0].payload).toEqual(p1);
    expect(events[1].payload).toEqual(p2);
    expect(events[0].ordinal).toBe(0n);
    expect(events[1].ordinal).toBe(1n);
  });

  it("poll with cursor returns only newer messages", async () => {
    await store.provision(alice);
    const sender = dummyAID("Bob");

    for (let i = 0; i < 5; i++) {
      await ingress.submit({
        sender,
        recipient: alice,
        topic: "log",
        payload: new Uint8Array([i]),
      });
    }

    const events: EgressEvent[] = [];
    for await (const ev of egress.poll({
      recipient: alice,
      cursors: new Map([["log", 3n]]),
    })) {
      events.push(ev);
    }

    expect(events).toHaveLength(2);
    expect(events[0].ordinal).toBe(3n);
    expect(events[1].ordinal).toBe(4n);
  });

  it("provisioner.isAuthorized / listAuthorized reflect store state", async () => {
    expect(await provisioner.isAuthorized(alice)).toBe(false);
    expect(await provisioner.listAuthorized()).toHaveLength(0);

    await store.provision(alice);

    expect(await provisioner.isAuthorized(alice)).toBe(true);
    expect(await provisioner.listAuthorized()).toContain(alice);
  });
});

/**
 * Integration scenario:
 *   challenge-response authenticated poll
 */
describe("Challenge-response authenticated polling", () => {
  it("allows poll when valid signature is provided", async () => {
    const kp = await generateKeyPair();
    const alice = dummyAID("Alice");
    const mailboxAid = dummyAID("Mailbox");

    const store = new MemoryMailboxStore();
    const resolver = new MockKeyStateResolver(
      new Map([[alice, makeKeyState(kp.verferQb64)]]),
    );
    const ingress = new MailboxIngress({ store, resolver });
    const egress = new MailboxEgress({ store, resolver });

    await store.provision(alice);
    const payload = new TextEncoder().encode("secret message");
    await ingress.submit({
      sender: dummyAID("Bob"),
      recipient: alice,
      topic: "inbox",
      payload,
    });

    const nonce = generateNonce();
    const sigBytes = await signMessage(
      kp.privateKey,
      new TextEncoder().encode(nonce),
    );
    const sigQb64 = encodeEd25519IndexedSig(sigBytes, 0);

    const events: EgressEvent[] = [];
    for await (const ev of egress.poll({
      recipient: alice,
      cursors: new Map([["inbox", 0n]]),
      challenge: nonce,
      signature: sigQb64,
    })) {
      events.push(ev);
    }

    expect(events).toHaveLength(1);
    expect(events[0].payload).toEqual(payload);
  });

  it("rejects poll with invalid signature", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const alice = dummyAID("Alice");

    const store = new MemoryMailboxStore();
    const resolver = new MockKeyStateResolver(
      new Map([[alice, makeKeyState(kp1.verferQb64)]]),
    );
    const egress = new MailboxEgress({ store, resolver });

    await store.provision(alice);

    const nonce = generateNonce();
    // Sign with wrong key
    const sigBytes = await signMessage(
      kp2.privateKey,
      new TextEncoder().encode(nonce),
    );
    const sigQb64 = encodeEd25519IndexedSig(sigBytes, 0);

    await expect(
      (async () => {
        for await (const _ of egress.poll({
          recipient: alice,
          cursors: new Map([["inbox", 0n]]),
          challenge: nonce,
          signature: sigQb64,
        })) {
          // should not reach here
        }
      })(),
    ).rejects.toThrow(/authentication failed/i);
  });
});

/**
 * Integration scenario:
 *   MailboxProvisioner.processAuthorization with a real KERI reply
 */
describe("MailboxProvisioner.processAuthorization", () => {
  it("provisions an AID from a valid signed /end/role/add reply", async () => {
    const kp = await generateKeyPair();
    const controllerAid = dummyAID("Alice");
    const mailboxAid = dummyAID("Mailbox");

    const store = new MemoryMailboxStore();
    const resolver = new MockKeyStateResolver(
      new Map([[controllerAid, makeKeyState(kp.verferQb64)]]),
    );
    const provisioner = new MailboxProvisioner({ store, resolver, mailboxAid });

    // Build the KERI reply JSON
    const replyBytes = makeKeriJson({
      t: "rpy",
      d: "EABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
      dt: "2026-01-01T00:00:00.000000+00:00",
      r: "/end/role/add",
      a: {
        cid: controllerAid,
        role: "mailbox",
        eid: mailboxAid,
      },
    });

    // Sign the body bytes and attach a ControllerIdxSigs group
    const sigBytes = await signMessage(kp.privateKey, replyBytes);
    const sigQb64 = encodeEd25519IndexedSig(sigBytes, 0);

    // Build CESR attachment: -AAB (ControllerIdxSigs, count=1) + indexed sig
    // Counter code -AAB = "-AAB" prefix for 1 indexed sig
    const attachmentStr = `-AAB${sigQb64}`;
    const attachmentBytes = new TextEncoder().encode(attachmentStr);

    const combined = new Uint8Array(
      replyBytes.length + attachmentBytes.length,
    );
    combined.set(replyBytes);
    combined.set(attachmentBytes, replyBytes.length);

    const result = await provisioner.processAuthorization(combined);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.aid).toBe(controllerAid);
    }
    expect(await store.isProvisioned(controllerAid)).toBe(true);
  });

  it("rejects a reply with wrong route", async () => {
    const store = new MemoryMailboxStore();
    const resolver = new MockKeyStateResolver();
    const mailboxAid = dummyAID("Mailbox");
    const provisioner = new MailboxProvisioner({ store, resolver, mailboxAid });

    const bytes = makeKeriJson({ t: "rpy", r: "/end/role/wrong", a: {} });
    const result = await provisioner.processAuthorization(bytes);
    expect(result.ok).toBe(false);
    expect((result as { ok: false; reason: string }).reason).toMatch(/route/i);
  });

  it("rejects a reply addressed to a different mailbox", async () => {
    const store = new MemoryMailboxStore();
    const resolver = new MockKeyStateResolver();
    const mailboxAid = dummyAID("Mailbox");
    const otherMailbox = dummyAID("OtherMailbox");
    const provisioner = new MailboxProvisioner({ store, resolver, mailboxAid });

    const bytes = makeKeriJson({
      t: "rpy",
      r: "/end/role/add",
      a: {
        cid: dummyAID("Alice"),
        role: "mailbox",
        eid: otherMailbox,
      },
    });
    const result = await provisioner.processAuthorization(bytes);
    expect(result.ok).toBe(false);
  });

  it("rejects a reply with unresolvable controller key state", async () => {
    const store = new MemoryMailboxStore();
    const resolver = new MockKeyStateResolver(); // empty — no keys
    const mailboxAid = dummyAID("Mailbox");
    const provisioner = new MailboxProvisioner({ store, resolver, mailboxAid });

    const bytes = makeKeriJson({
      t: "rpy",
      r: "/end/role/add",
      a: {
        cid: dummyAID("Alice"),
        role: "mailbox",
        eid: mailboxAid,
      },
    });
    const result = await provisioner.processAuthorization(bytes);
    expect(result.ok).toBe(false);
    expect((result as { ok: false; reason: string }).reason).toMatch(/key state/i);
  });
});
