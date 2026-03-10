import { describe, it, expect, beforeEach } from "vitest";
import type { HashFn } from "cesr-ts";
import { InceptionBuilder } from "../../src/builders/InceptionBuilder.js";
import { RotationBuilder } from "../../src/builders/RotationBuilder.js";
import { InteractionBuilder } from "../../src/builders/InteractionBuilder.js";
import { signEvent } from "../../src/pipeline/SignedEvent.js";
import { VerificationPipeline } from "../../src/pipeline/VerificationPipeline.js";
import { MemoryEventDatabase } from "../../src/memory/MemoryEventDatabase.js";
import { Kever } from "../../src/core/state/Kever.js";
import { KeyStateView } from "../../src/views/KeyState.js";
import type { ICryptoProvider } from "../../src/interfaces/ICryptoProvider.js";
import { generateKeyPair, signMessage, type Ed25519KeyPair } from "../helpers.js";

function testHash(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(32);
  for (let i = 0; i < data.length; i++) {
    result[i % 32] ^= data[i];
  }
  return result;
}

const hashFn: HashFn = testHash;

const mockCrypto: ICryptoProvider = {
  async verifySignature(pubKey, sig, msg) {
    return crypto.subtle
      .importKey("raw", pubKey.slice(), { name: "Ed25519" }, false, ["verify"])
      .then((key) => crypto.subtle.verify("Ed25519", key, sig.slice(), msg.slice()))
      .catch(() => false);
  },
  async digest(data) {
    const hash = await crypto.subtle.digest("SHA-256", data.slice());
    return new Uint8Array(hash);
  },
};

describe("Inception → Rotation → Interaction flow", () => {
  let kp1: Ed25519KeyPair;
  let kp2: Ed25519KeyPair;
  let kp3: Ed25519KeyPair;
  let db: MemoryEventDatabase;
  let pipeline: VerificationPipeline;

  beforeEach(async () => {
    kp1 = await generateKeyPair();
    kp2 = await generateKeyPair();
    kp3 = await generateKeyPair();
    db = new MemoryEventDatabase();
    pipeline = new VerificationPipeline({
      db,
      crypto: mockCrypto,
      hashFn,
    });
  });

  it("processes a full icp → rot → ixn lifecycle", async () => {
    // 1. Inception
    const icpEvent = new InceptionBuilder(hashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    const signedIcp = await signEvent(icpEvent, [
      { index: 0, sign: (m: Uint8Array) => signMessage(kp1.privateKey, m) },
    ]);

    const icpResult = await pipeline.verify(
      signedIcp.event.raw,
      signedIcp.event.fields,
      signedIcp.sigers,
    );

    expect(icpResult.type).toBe("accepted");
    if (icpResult.type !== "accepted") return;
    expect(icpResult.sn).toBe(0);

    const prefix = icpResult.prefix;
    const icpSaid = icpResult.said;

    // Verify event stored in DB
    const storedEvent = await db.getEvent(prefix, icpSaid);
    expect(storedEvent).toBeTruthy();

    // 2. Rotation — kp1 → kp2, pre-rotate to kp3
    // Need to add the kever to the pipeline for sequence checking
    const kever = new Kever();
    kever.incept(signedIcp.event.fields);
    const kevers = new Map<string, Kever>();
    kevers.set(prefix, kever);

    const pipeline2 = new VerificationPipeline({
      db,
      crypto: mockCrypto,
      hashFn,
      kevers,
    });

    const rotEvent = new RotationBuilder(hashFn)
      .identifier(prefix)
      .sequenceNumber(1)
      .previousEvent(icpSaid)
      .signingKeys([kp2.verferQb64])
      .nextKeys([kp3.verferQb64])
      .build();

    const signedRot = await signEvent(rotEvent, [
      { index: 0, sign: (m: Uint8Array) => signMessage(kp2.privateKey, m) },
    ]);

    const rotResult = await pipeline2.verify(
      signedRot.event.raw,
      signedRot.event.fields,
      signedRot.sigers,
    );

    expect(rotResult.type).toBe("accepted");
    if (rotResult.type !== "accepted") return;
    expect(rotResult.sn).toBe(1);

    // 3. Interaction
    kever.update(signedRot.event.fields);

    const ixnEvent = new InteractionBuilder(hashFn)
      .identifier(prefix)
      .sequenceNumber(2)
      .previousEvent(rotResult.said)
      .anchoredSeals([{ i: "Eother", s: "0", d: "Eother_said" }])
      .build();

    const signedIxn = await signEvent(ixnEvent, [
      { index: 0, sign: (m: Uint8Array) => signMessage(kp2.privateKey, m) },
    ]);

    const ixnResult = await pipeline2.verify(
      signedIxn.event.raw,
      signedIxn.event.fields,
      signedIxn.sigers,
    );

    expect(ixnResult.type).toBe("accepted");
    if (ixnResult.type !== "accepted") return;
    expect(ixnResult.sn).toBe(2);
  });

  it("verifies key state view after inception", async () => {
    const icpEvent = new InceptionBuilder(hashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .build();

    const kever = new Kever();
    kever.incept(icpEvent.fields);
    const ksr = kever.toKeyStateRecord();
    const view = new KeyStateView(ksr);

    expect(view.identifier).toBe(icpEvent.prefix);
    expect(view.sequenceNumber).toBe(0);
    expect(view.signingKeys).toEqual([kp1.verferQb64]);
    expect(view.nextKeyDigests).toEqual([kp2.verferQb64]);
    expect(view.isTransferable).toBe(true);
    expect(view.isDelegated).toBe(false);
    expect(view.isEstablishmentOnly).toBe(false);
  });

  it("creates non-transferable identifier (no next keys)", async () => {
    const icpEvent = new InceptionBuilder(hashFn)
      .signingKeys([kp1.verferQb64])
      // No nextKeys → non-transferable
      .build();

    const kever = new Kever();
    kever.incept(icpEvent.fields);
    const ksr = kever.toKeyStateRecord();
    const view = new KeyStateView(ksr);

    expect(view.isTransferable).toBe(false);
    expect(view.nextKeyDigests).toEqual([]);
  });

  it("creates establishment-only identifier", async () => {
    const icpEvent = new InceptionBuilder(hashFn)
      .signingKeys([kp1.verferQb64])
      .nextKeys([kp2.verferQb64])
      .establishmentOnly()
      .build();

    const kever = new Kever();
    kever.incept(icpEvent.fields);
    const ksr = kever.toKeyStateRecord();
    const view = new KeyStateView(ksr);

    expect(view.isEstablishmentOnly).toBe(true);
    expect(view.configTraits).toContain("EO");
  });
});

describe("Multi-signature threshold", () => {
  it("handles 2-of-3 multi-sig inception", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();
    const nextKp = await generateKeyPair();

    const icpEvent = new InceptionBuilder(hashFn)
      .signingKeys([kp1.verferQb64, kp2.verferQb64, kp3.verferQb64])
      .signingThreshold("2")
      .nextKeys([nextKp.verferQb64])
      .build();

    expect(icpEvent.fields.kt).toBe("2");
    expect((icpEvent.fields.k as string[]).length).toBe(3);

    // Sign with 2 of 3 signers
    const signed = await signEvent(icpEvent, [
      { index: 0, sign: (m: Uint8Array) => signMessage(kp1.privateKey, m) },
      { index: 2, sign: (m: Uint8Array) => signMessage(kp3.privateKey, m) },
    ]);

    expect(signed.sigers).toHaveLength(2);
    expect(signed.sigers[0].index).toBe(0);
    expect(signed.sigers[1].index).toBe(2);

    const db = new MemoryEventDatabase();
    const pipeline = new VerificationPipeline({
      db,
      crypto: mockCrypto,
      hashFn,
    });

    const result = await pipeline.verify(
      signed.event.raw,
      signed.event.fields,
      signed.sigers,
    );

    expect(result.type).toBe("accepted");
  });

  it("escrows with insufficient signatures (1-of-3 when 2 required)", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const kp3 = await generateKeyPair();

    const icpEvent = new InceptionBuilder(hashFn)
      .signingKeys([kp1.verferQb64, kp2.verferQb64, kp3.verferQb64])
      .signingThreshold("2")
      .build();

    // Only sign with 1 signer
    const signed = await signEvent(icpEvent, [
      { index: 0, sign: (m: Uint8Array) => signMessage(kp1.privateKey, m) },
    ]);

    const db = new MemoryEventDatabase();
    const pipeline = new VerificationPipeline({
      db,
      crypto: mockCrypto,
      hashFn,
    });

    const result = await pipeline.verify(
      signed.event.raw,
      signed.event.fields,
      signed.sigers,
    );

    expect(result.type).toBe("escrowed");
    if (result.type === "escrowed") {
      expect(result.reason).toBe("partial_signatures");
    }
  });
});
