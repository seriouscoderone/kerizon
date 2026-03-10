import { describe, it, expect } from "vitest";
import type { HashFn } from "cesr-ts";
import { InceptionBuilder } from "../../../src/builders/InceptionBuilder.js";
import { RotationBuilder } from "../../../src/builders/RotationBuilder.js";
import { InteractionBuilder } from "../../../src/builders/InteractionBuilder.js";
import { DelegatedInceptionBuilder } from "../../../src/builders/DelegatedInceptionBuilder.js";
import { DelegatedRotationBuilder } from "../../../src/builders/DelegatedRotationBuilder.js";
import { ReceiptBuilder } from "../../../src/builders/ReceiptBuilder.js";
import { StructuralError, SequenceError, WitnessError } from "../../../src/types/errors.js";

// Deterministic hash: SHA-256 via Web Crypto made synchronous-ish for saidify.
// cesr-ts saidify expects a synchronous HashFn, so we use a simple deterministic hash.
function testHash(data: Uint8Array): Uint8Array {
  // Simple deterministic 32-byte hash for testing
  const result = new Uint8Array(32);
  for (let i = 0; i < data.length; i++) {
    result[i % 32] ^= data[i];
  }
  return result;
}

const hashFn: HashFn = testHash;

const fakeKey1 = "D" + "A".repeat(43);
const fakeKey2 = "D" + "B".repeat(43);
const fakeKey3 = "D" + "C".repeat(43);
const fakeWit1 = "B" + "w".repeat(43);
const fakeWit2 = "B" + "x".repeat(43);
const fakeWit3 = "B" + "y".repeat(43);

describe("InceptionBuilder", () => {
  it("builds a basic inception event", () => {
    const event = new InceptionBuilder(hashFn)
      .signingKeys([fakeKey1])
      .nextKeys([fakeKey2])
      .build();

    expect(event.ilk).toBe("icp");
    expect(event.sn).toBe(0);
    expect(event.fields.t).toBe("icp");
    expect(event.fields.k).toEqual([fakeKey1]);
    expect(event.fields.n).toEqual([fakeKey2]);
    expect(event.fields.kt).toBe("1");
    expect(event.fields.s).toBe("0");
    expect(event.prefix).toBeTruthy();
    expect(event.said).toBeTruthy();
    expect(event.raw).toBeInstanceOf(Uint8Array);
  });

  it("defaults signing threshold to ceil(n/2)", () => {
    const event = new InceptionBuilder(hashFn)
      .signingKeys([fakeKey1, fakeKey2, fakeKey3])
      .build();

    expect(event.fields.kt).toBe("2"); // ceil(3/2) = 2
  });

  it("supports custom thresholds", () => {
    const event = new InceptionBuilder(hashFn)
      .signingKeys([fakeKey1, fakeKey2])
      .signingThreshold("1")
      .nextKeys([fakeKey3])
      .nextKeyThreshold("1")
      .build();

    expect(event.fields.kt).toBe("1");
    expect(event.fields.nt).toBe("1");
  });

  it("supports witnesses", () => {
    const event = new InceptionBuilder(hashFn)
      .signingKeys([fakeKey1])
      .witnesses([fakeWit1, fakeWit2, fakeWit3])
      .build();

    expect(event.fields.b).toEqual([fakeWit1, fakeWit2, fakeWit3]);
    // bt should be hex of ample(3) = 2
    expect(event.fields.bt).toBe("2");
  });

  it("supports config traits", () => {
    const event = new InceptionBuilder(hashFn)
      .signingKeys([fakeKey1])
      .establishmentOnly()
      .doNotDelegate()
      .build();

    expect(event.fields.c).toEqual(["EO", "DND"]);
  });

  it("throws when no signing keys", () => {
    expect(() => new InceptionBuilder(hashFn).build()).toThrow(StructuralError);
  });

  it("throws for out-of-range threshold", () => {
    expect(() =>
      new InceptionBuilder(hashFn)
        .signingKeys([fakeKey1])
        .signingThreshold("3")
        .build(),
    ).toThrow(StructuralError);
  });

  it("throws for duplicate witnesses", () => {
    expect(() =>
      new InceptionBuilder(hashFn)
        .signingKeys([fakeKey1])
        .witnesses([fakeWit1, fakeWit1])
        .build(),
    ).toThrow(WitnessError);
  });

  it("sets i and d to same SAID for inception", () => {
    const event = new InceptionBuilder(hashFn)
      .signingKeys([fakeKey1])
      .nextKeys([fakeKey2])
      .build();

    expect(event.fields.d).toBe(event.fields.i);
    expect(event.prefix).toBe(event.said);
  });
});

describe("RotationBuilder", () => {
  it("builds a rotation event", () => {
    const event = new RotationBuilder(hashFn)
      .identifier("Eprefix123")
      .sequenceNumber(1)
      .previousEvent("Eprev_said")
      .signingKeys([fakeKey2])
      .nextKeys([fakeKey3])
      .build();

    expect(event.ilk).toBe("rot");
    expect(event.sn).toBe(1);
    expect(event.fields.t).toBe("rot");
    expect(event.fields.i).toBe("Eprefix123");
    expect(event.fields.p).toBe("Eprev_said");
    expect(event.fields.k).toEqual([fakeKey2]);
    expect(event.prefix).toBe("Eprefix123");
  });

  it("throws when missing identifier", () => {
    expect(() =>
      new RotationBuilder(hashFn)
        .sequenceNumber(1)
        .previousEvent("Eprev")
        .signingKeys([fakeKey1])
        .build(),
    ).toThrow(StructuralError);
  });

  it("throws when sn < 1", () => {
    expect(() =>
      new RotationBuilder(hashFn)
        .identifier("Eprefix")
        .sequenceNumber(0)
        .previousEvent("Eprev")
        .signingKeys([fakeKey1])
        .build(),
    ).toThrow(SequenceError);
  });

  it("throws when missing previous event", () => {
    expect(() =>
      new RotationBuilder(hashFn)
        .identifier("Eprefix")
        .sequenceNumber(1)
        .signingKeys([fakeKey1])
        .build(),
    ).toThrow(StructuralError);
  });

  it("supports witness changes", () => {
    const event = new RotationBuilder(hashFn)
      .identifier("Eprefix")
      .sequenceNumber(1)
      .previousEvent("Eprev")
      .signingKeys([fakeKey2])
      .currentWitnesses([fakeWit1, fakeWit2])
      .cutWitnesses([fakeWit1])
      .addWitnesses([fakeWit3])
      .build();

    expect(event.fields.br).toEqual([fakeWit1]);
    expect(event.fields.ba).toEqual([fakeWit3]);
  });
});

describe("InteractionBuilder", () => {
  it("builds an interaction event", () => {
    const event = new InteractionBuilder(hashFn)
      .identifier("Eprefix")
      .sequenceNumber(2)
      .previousEvent("Eprev")
      .build();

    expect(event.ilk).toBe("ixn");
    expect(event.sn).toBe(2);
    expect(event.fields.t).toBe("ixn");
    expect(event.fields.a).toEqual([]);
  });

  it("supports anchored seals", () => {
    const seal = { i: "Eseal", s: "0", d: "Esaid" };
    const event = new InteractionBuilder(hashFn)
      .identifier("Eprefix")
      .sequenceNumber(1)
      .previousEvent("Eprev")
      .anchoredSeals([seal])
      .build();

    expect(event.fields.a).toEqual([seal]);
  });

  it("throws when missing identifier", () => {
    expect(() =>
      new InteractionBuilder(hashFn)
        .sequenceNumber(1)
        .previousEvent("Eprev")
        .build(),
    ).toThrow(StructuralError);
  });

  it("throws when sn < 1", () => {
    expect(() =>
      new InteractionBuilder(hashFn)
        .identifier("Eprefix")
        .sequenceNumber(0)
        .previousEvent("Eprev")
        .build(),
    ).toThrow(SequenceError);
  });
});

describe("DelegatedInceptionBuilder", () => {
  it("builds a dip event with delegator", () => {
    const event = new DelegatedInceptionBuilder(hashFn)
      .delegator("Edelegator")
      .signingKeys([fakeKey1])
      .nextKeys([fakeKey2])
      .build();

    expect(event.ilk).toBe("dip");
    expect(event.sn).toBe(0);
    expect(event.fields.di).toBe("Edelegator");
    expect(event.fields.d).toBe(event.fields.i); // dual SAID
  });

  it("throws when missing delegator", () => {
    expect(() =>
      new DelegatedInceptionBuilder(hashFn)
        .signingKeys([fakeKey1])
        .build(),
    ).toThrow(StructuralError);
  });
});

describe("DelegatedRotationBuilder", () => {
  it("builds a drt event", () => {
    const event = new DelegatedRotationBuilder(hashFn)
      .identifier("Eprefix")
      .sequenceNumber(1)
      .previousEvent("Eprev")
      .signingKeys([fakeKey2])
      .build();

    expect(event.ilk).toBe("drt");
    expect(event.fields.t).toBe("drt");
  });

  it("throws when sn < 1", () => {
    expect(() =>
      new DelegatedRotationBuilder(hashFn)
        .identifier("Eprefix")
        .sequenceNumber(0)
        .previousEvent("Eprev")
        .signingKeys([fakeKey1])
        .build(),
    ).toThrow(SequenceError);
  });
});

describe("ReceiptBuilder", () => {
  it("builds a receipt event", () => {
    const event = new ReceiptBuilder()
      .forEvent({ prefix: "Eprefix", sn: 0, said: "Esaid" })
      .build();

    expect(event.ilk).toBe("rct");
    expect(event.fields.t).toBe("rct");
    expect(event.fields.i).toBe("Eprefix");
    expect(event.fields.d).toBe("Esaid");
    expect(event.fields.s).toBe("0");
    expect(event.sn).toBe(0);
    expect(event.prefix).toBe("Eprefix");
  });
});
