import { describe, it, expect } from "vitest";
import { Kevery } from "../../../src/core/processing/Kevery.js";
import { MemoryEventDatabase } from "../../../src/memory/MemoryEventDatabase.js";
import {
  OutOfOrderError,
  DuplicityError,
} from "../../../src/types/errors.js";
import type { ICryptoProvider } from "../../../src/interfaces/ICryptoProvider.js";

const testCrypto: ICryptoProvider = {
  async verifySignature(publicKeyBytes, signatureBytes, message) {
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes.slice(),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        "Ed25519",
        key,
        signatureBytes.slice(),
        message.slice(),
      );
    } catch {
      return false;
    }
  },
  async digest(data) {
    const hash = await crypto.subtle.digest("SHA-256", data.slice());
    return new Uint8Array(hash);
  },
};

function makeIcpFields(): Record<string, unknown> {
  return {
    v: "KERI10JSON000120_",
    t: "icp",
    d: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    i: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    s: "0",
    kt: "1",
    k: ["DGBw9oJIm2eM-iHKGsLXFBKJwa4mRGHqtCrP69BO6O0g"],
    nt: "1",
    n: ["EMQQx1qz-HCuHMsCHJK5bnkAt-oq6jGpivdPazusJvas"],
    bt: "0",
    b: [],
    c: [],
    a: [],
  };
}

function makeIxnFields(sn: number, prior: string, said: string): Record<string, unknown> {
  return {
    v: "KERI10JSON000098_",
    t: "ixn",
    d: said,
    i: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    s: sn.toString(16),
    p: prior,
    a: [],
  };
}

function makeRotFields(sn: number, prior: string, said: string): Record<string, unknown> {
  return {
    v: "KERI10JSON000160_",
    t: "rot",
    d: said,
    i: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    s: sn.toString(16),
    p: prior,
    kt: "1",
    k: ["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],
    nt: "1",
    n: ["ENJPEMECFaXg7FXHM4-L3tFWJr636TZGwB3BilcUnfM_"],
    bt: "0",
    br: [],
    ba: [],
    a: [],
  };
}

function serialize(fields: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(fields));
}

describe("Kevery", () => {
  it("processes an inception event", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });
    const fields = makeIcpFields();

    const ksr = await kevery.processEvent(serialize(fields), fields);

    expect(ksr.i).toBe("EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo");
    expect(ksr.s).toBe("0");
    expect(ksr.et).toBe("icp");
    expect(kevery.kevers.has(ksr.i)).toBe(true);
    expect(kevery.cues).toHaveLength(1);
    expect(kevery.cues[0].kind).toBe("receipt");
  });

  it("rejects non-inception event before inception", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });
    const fields = makeIxnFields(1, "EABC", "EDEF");

    await expect(
      kevery.processEvent(serialize(fields), fields),
    ).rejects.toThrow(OutOfOrderError);
  });

  it("processes inception then interaction", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });

    const icpFields = makeIcpFields();
    const icpSaid = "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo";
    await kevery.processEvent(serialize(icpFields), icpFields);

    const ixnFields = makeIxnFields(1, icpSaid, "EIXN1_SAID_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const ksr = await kevery.processEvent(serialize(ixnFields), ixnFields);

    expect(ksr.s).toBe("1");
    expect(ksr.et).toBe("ixn");
    // Key state unchanged
    expect(ksr.k).toEqual(["DGBw9oJIm2eM-iHKGsLXFBKJwa4mRGHqtCrP69BO6O0g"]);
  });

  it("processes inception then rotation", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });

    const icpFields = makeIcpFields();
    const icpSaid = "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo";
    await kevery.processEvent(serialize(icpFields), icpFields);

    const rotFields = makeRotFields(1, icpSaid, "EROT1_SAID_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const ksr = await kevery.processEvent(serialize(rotFields), rotFields);

    expect(ksr.s).toBe("1");
    expect(ksr.et).toBe("rot");
    expect(ksr.k).toEqual(["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"]);
    expect(ksr.ee.s).toBe("1");
  });

  it("throws OutOfOrderError for future event", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });

    const icpFields = makeIcpFields();
    await kevery.processEvent(serialize(icpFields), icpFields);

    // Jump to sn=5 (expected sn=1)
    const ixnFields = makeIxnFields(5, "EABC", "EFUTURE");
    await expect(
      kevery.processEvent(serialize(ixnFields), ixnFields),
    ).rejects.toThrow(OutOfOrderError);
  });

  it("throws DuplicityError for different inception at same prefix", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });

    const icpFields = makeIcpFields();
    await kevery.processEvent(serialize(icpFields), icpFields);

    // Same prefix (i) but different SAID (d) — duplicitous inception
    const dupFields = {
      ...icpFields,
      d: "EDUPLICIT_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      // i stays the same prefix
    };
    await expect(
      kevery.processEvent(serialize(dupFields), dupFields),
    ).rejects.toThrow(DuplicityError);
  });

  it("accepts duplicate inception idempotently", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });

    const icpFields = makeIcpFields();
    const ksr1 = await kevery.processEvent(serialize(icpFields), icpFields);
    const ksr2 = await kevery.processEvent(serialize(icpFields), icpFields);

    expect(ksr1.i).toBe(ksr2.i);
  });

  it("assigns sequential first-seen ordinals", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });

    const icpFields = makeIcpFields();
    const icpSaid = "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo";
    await kevery.processEvent(serialize(icpFields), icpFields);

    const ixnFields = makeIxnFields(1, icpSaid, "EIXN1");
    await kevery.processEvent(serialize(ixnFields), ixnFields);

    const fn0 = await db.getFn("EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo", icpSaid);
    const fn1 = await db.getFn("EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo", "EIXN1");

    expect(fn0).toBe(0);
    expect(fn1).toBe(1);
  });

  it("stores events in database", async () => {
    const db = new MemoryEventDatabase();
    const kevery = new Kevery({ db, crypto: testCrypto });

    const icpFields = makeIcpFields();
    const icpSaid = "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo";
    await kevery.processEvent(serialize(icpFields), icpFields);

    const stored = await db.getEvent(icpSaid, icpSaid);
    expect(stored).toBeDefined();

    const kelEntry = await db.getKelEntry(icpSaid, 0);
    expect(kelEntry).toContain(icpSaid);
  });
});
