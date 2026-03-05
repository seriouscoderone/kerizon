import { describe, it, expect } from "vitest";
import type { HashFn } from "cesr-ts";
import { signEvent } from "../../../src/pipeline/SignedEvent.js";
import { VerificationPipeline } from "../../../src/pipeline/VerificationPipeline.js";
import { MemoryEventDatabase } from "../../../src/memory/MemoryEventDatabase.js";
import { InceptionBuilder } from "../../../src/builders/InceptionBuilder.js";
import { InteractionBuilder } from "../../../src/builders/InteractionBuilder.js";
import { RotationBuilder } from "../../../src/builders/RotationBuilder.js";
import { KeyStateView } from "../../../src/views/KeyState.js";
import type { KeyStateRecord } from "../../../src/types/KeyStateRecord.js";
import type { ICryptoProvider } from "../../../src/interfaces/ICryptoProvider.js";
import { generateKeyPair, signMessage, encodeEd25519Verfer } from "../../helpers.js";

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

describe("signEvent", () => {
  it("produces indexed sigers from signers", async () => {
    const kp = await generateKeyPair();

    const event = new InceptionBuilder(hashFn)
      .signingKeys([kp.verferQb64])
      .build();

    const signed = await signEvent(event, [
      {
        index: 0,
        async sign(message: Uint8Array) {
          return signMessage(kp.privateKey, message);
        },
      },
    ]);

    expect(signed.event).toBe(event);
    expect(signed.sigers).toHaveLength(1);
    expect(signed.sigers[0].index).toBe(0);
    expect(signed.sigers[0].raw).toBeInstanceOf(Uint8Array);
    expect(signed.sigers[0].raw.length).toBe(64);
    expect(signed.sigers[0].qb64).toMatch(/^sig_0_/);
  });

  it("supports multiple signers", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();

    const event = new InceptionBuilder(hashFn)
      .signingKeys([kp1.verferQb64, kp2.verferQb64])
      .build();

    const signed = await signEvent(event, [
      { index: 0, sign: (m: Uint8Array) => signMessage(kp1.privateKey, m) },
      { index: 1, sign: (m: Uint8Array) => signMessage(kp2.privateKey, m) },
    ]);

    expect(signed.sigers).toHaveLength(2);
    expect(signed.sigers[0].index).toBe(0);
    expect(signed.sigers[1].index).toBe(1);
  });
});

describe("VerificationPipeline", () => {
  it("accepts a valid inception event", async () => {
    const kp = await generateKeyPair();
    const db = new MemoryEventDatabase();

    const event = new InceptionBuilder(hashFn)
      .signingKeys([kp.verferQb64])
      .build();

    const signed = await signEvent(event, [
      { index: 0, sign: (m: Uint8Array) => signMessage(kp.privateKey, m) },
    ]);

    const pipeline = new VerificationPipeline({ db, crypto: mockCrypto, hashFn });
    const result = await pipeline.verify(
      signed.event.raw,
      signed.event.fields,
      signed.sigers,
    );

    expect(result.type).toBe("accepted");
    if (result.type === "accepted") {
      expect(result.sn).toBe(0);
      expect(result.prefix).toBeTruthy();
    }
  });

  it("rejects event with invalid structure (bad sn for inception)", async () => {
    const db = new MemoryEventDatabase();
    const pipeline = new VerificationPipeline({ db, crypto: mockCrypto, hashFn });

    // Build raw fields with sn=1 for inception (should reject)
    const fields: Record<string, unknown> = {
      v: "KERI10JSON000100_",
      t: "icp",
      d: "Efake",
      i: "Efake",
      s: "1", // Invalid: inception must be sn=0
      kt: "1",
      k: ["Dkey"],
      nt: "0",
      n: [],
      bt: "0",
      b: [],
      c: [],
      a: [],
    };
    const raw = new TextEncoder().encode(JSON.stringify(fields));
    const result = await pipeline.verify(raw, fields, []);

    expect(result.type).toBe("rejected");
  });

  it("escrows out-of-order event (no inception found)", async () => {
    const db = new MemoryEventDatabase();
    const pipeline = new VerificationPipeline({ db, crypto: mockCrypto, hashFn });

    // Build a real ixn using the builder so it passes structural validation
    const ixnEvent = new InteractionBuilder(hashFn)
      .identifier("Eprefix_not_found_yet")
      .sequenceNumber(1)
      .previousEvent("Eprev_said")
      .build();

    const result = await pipeline.verify(ixnEvent.raw, ixnEvent.fields, []);

    expect(result.type).toBe("escrowed");
    if (result.type === "escrowed") {
      expect(result.reason).toBe("out_of_order");
    }
  });
});

describe("KeyStateView", () => {
  it("wraps a KeyStateRecord with readable properties", () => {
    const ksr: KeyStateRecord = {
      v: "KERI10JSON000000_",
      vn: [1, 0],
      i: "Eprefix123",
      s: "3",
      p: "Eprev",
      d: "Esaid",
      f: "a",
      dt: "2026-03-04T00:00:00.000Z",
      et: "rot",
      kt: "2",
      k: ["Dkey1", "Dkey2", "Dkey3"],
      nt: "1",
      n: ["Enext1"],
      bt: "2",
      b: ["Bwit1", "Bwit2", "Bwit3"],
      c: ["EO"],
      ee: { s: "2", d: "Eest_said", br: [], ba: [] },
      di: "",
    };

    const view = new KeyStateView(ksr);
    expect(view.identifier).toBe("Eprefix123");
    expect(view.sequenceNumber).toBe(3);
    expect(view.latestEventSaid).toBe("Esaid");
    expect(view.priorEventSaid).toBe("Eprev");
    expect(view.signingKeys).toEqual(["Dkey1", "Dkey2", "Dkey3"]);
    expect(view.signingThreshold).toBe("2");
    expect(view.nextKeyDigests).toEqual(["Enext1"]);
    expect(view.witnesses).toEqual(["Bwit1", "Bwit2", "Bwit3"]);
    expect(view.witnessThreshold).toBe(2);
    expect(view.firstSeenOrdinal).toBe(0xa);
    expect(view.firstSeenDatetime).toBe("2026-03-04T00:00:00.000Z");
    expect(view.isTransferable).toBe(true);
    expect(view.isDelegated).toBe(false);
    expect(view.isEstablishmentOnly).toBe(true);
    expect(view.isDoNotDelegate).toBe(false);
    expect(view.lastEstablishmentSn).toBe(2);
    expect(view.configTraits).toEqual(["EO"]);
    expect(view.toRecord()).toBe(ksr);
  });

  it("detects non-transferable identifier", () => {
    const ksr: KeyStateRecord = {
      v: "KERI10JSON000000_",
      vn: [1, 0],
      i: "Eprefix",
      s: "0",
      p: "",
      d: "Esaid",
      f: "0",
      dt: "2026-03-04T00:00:00.000Z",
      et: "icp",
      kt: "1",
      k: ["Dkey1"],
      nt: "0",
      n: [], // No next keys = non-transferable
      bt: "0",
      b: [],
      c: [],
      ee: { s: "0", d: "Esaid", br: [], ba: [] },
      di: "",
    };

    const view = new KeyStateView(ksr);
    expect(view.isTransferable).toBe(false);
  });

  it("detects delegated identifier", () => {
    const ksr: KeyStateRecord = {
      v: "KERI10JSON000000_",
      vn: [1, 0],
      i: "Eprefix",
      s: "0",
      p: "",
      d: "Esaid",
      f: "0",
      dt: "2026-03-04T00:00:00.000Z",
      et: "dip",
      kt: "1",
      k: ["Dkey1"],
      nt: "0",
      n: [],
      bt: "0",
      b: [],
      c: [],
      ee: { s: "0", d: "Esaid", br: [], ba: [] },
      di: "Edelegator",
    };

    const view = new KeyStateView(ksr);
    expect(view.isDelegated).toBe(true);
    expect(view.delegator).toBe("Edelegator");
  });
});
