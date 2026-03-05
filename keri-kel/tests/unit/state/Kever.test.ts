import { describe, it, expect } from "vitest";
import { Kever } from "../../../src/core/state/Kever.js";
import {
  StructuralError,
  SequenceError,
  ConfigError,
  WitnessError,
} from "../../../src/types/errors.js";

/** Helper to build minimal inception event fields. */
function makeIcpFields(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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
    ...overrides,
  };
}

/** Helper to build minimal rotation event fields. */
function makeRotFields(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: "KERI10JSON000160_",
    t: "rot",
    d: "ECJt66bVjJO-WP_GBgGrrkCc3GOQPK8Ll_pHWPJZiQeU",
    i: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    s: "1",
    p: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    kt: "1",
    k: ["DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A"],
    nt: "1",
    n: ["ENJPEMECFaXg7FXHM4-L3tFWJr636TZGwB3BilcUnfM_"],
    bt: "0",
    br: [],
    ba: [],
    a: [],
    ...overrides,
  };
}

/** Helper to build minimal interaction event fields. */
function makeIxnFields(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: "KERI10JSON000098_",
    t: "ixn",
    d: "EHqG9Z3At4tJicfkE_KDCf1gRo8JjQTMf1hVIk01xPeA",
    i: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    s: "1",
    p: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    a: [],
    ...overrides,
  };
}

describe("Kever.incept", () => {
  it("initializes from a valid inception event", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields());

    expect(kever.prefix).toBe("EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo");
    expect(kever.sn).toBe(0);
    expect(kever.signingKeys).toEqual([
      "DGBw9oJIm2eM-iHKGsLXFBKJwa4mRGHqtCrP69BO6O0g",
    ]);
    expect(kever.signingThreshold).toBe("1");
    expect(kever.nextKeyDigests).toEqual([
      "EMQQx1qz-HCuHMsCHJK5bnkAt-oq6jGpivdPazusJvas",
    ]);
    expect(kever.transferable).toBe(true);
    expect(kever.lastEst).toEqual({
      s: 0,
      d: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
    });
  });

  it("rejects non-zero sn for inception", () => {
    const kever = new Kever();
    expect(() => kever.incept(makeIcpFields({ s: "1" }))).toThrow(SequenceError);
  });

  it("rejects signing threshold > key count", () => {
    const kever = new Kever();
    expect(() => kever.incept(makeIcpFields({ kt: "5" }))).toThrow(
      StructuralError,
    );
  });

  it("rejects signing threshold < 1", () => {
    const kever = new Kever();
    expect(() => kever.incept(makeIcpFields({ kt: "0" }))).toThrow(
      StructuralError,
    );
  });

  it("rejects duplicate witnesses", () => {
    const kever = new Kever();
    expect(() =>
      kever.incept(
        makeIcpFields({
          bt: "1",
          b: ["Bwit1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "Bwit1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        }),
      ),
    ).toThrow(WitnessError);
  });

  it("rejects non-zero TOAD with empty witnesses", () => {
    const kever = new Kever();
    expect(() =>
      kever.incept(makeIcpFields({ bt: "1", b: [] })),
    ).toThrow(WitnessError);
  });

  it("marks non-transferable when next digests empty", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields({ nt: "0", n: [] }));
    expect(kever.transferable).toBe(false);
  });

  it("rejects non-transferable with witnesses", () => {
    const kever = new Kever();
    expect(() =>
      kever.incept(
        makeIcpFields({
          nt: "0",
          n: [],
          bt: "1",
          b: ["Bwit1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        }),
      ),
    ).toThrow(StructuralError);
  });

  it("parses EO and DND traits", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields({ c: ["EO", "DND"] }));
    expect(kever.estOnly).toBe(true);
    expect(kever.doNotDelegate).toBe(true);
  });

  it("handles delegated inception (dip)", () => {
    const kever = new Kever();
    kever.incept({
      ...makeIcpFields({ t: "dip" }),
      di: "EBfxDELEGATOR_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    expect(kever.delegated).toBe(true);
    expect(kever.delegatorPrefix).toBe(
      "EBfxDELEGATOR_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
  });
});

describe("Kever.update — interaction", () => {
  it("advances sn on interaction", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields());

    kever.update(makeIxnFields());
    expect(kever.sn).toBe(1);
    expect(kever.lastIlk).toBe("ixn");
    // Key state should be unchanged
    expect(kever.signingKeys).toEqual([
      "DGBw9oJIm2eM-iHKGsLXFBKJwa4mRGHqtCrP69BO6O0g",
    ]);
  });

  it("rejects interaction with wrong sn", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields());

    expect(() =>
      kever.update(makeIxnFields({ s: "3" })),
    ).toThrow(SequenceError);
  });

  it("rejects interaction with wrong prior SAID", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields());

    expect(() =>
      kever.update(makeIxnFields({ p: "EWRONG_SAID_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" })),
    ).toThrow(SequenceError);
  });

  it("rejects interaction when EO is set", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields({ c: ["EO"] }));

    expect(() => kever.update(makeIxnFields())).toThrow(ConfigError);
  });
});

describe("Kever.update — rotation", () => {
  it("updates key state on rotation", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields());

    kever.update(makeRotFields());
    expect(kever.sn).toBe(1);
    expect(kever.signingKeys).toEqual([
      "DHgZa-u7veNZkqk2AxCnxrINGKfQ0bRiaf9FdA_-_49A",
    ]);
    expect(kever.lastEst).toEqual({
      s: 1,
      d: "ECJt66bVjJO-WP_GBgGrrkCc3GOQPK8Ll_pHWPJZiQeU",
    });
  });

  it("derives witnesses on rotation with cuts and adds", () => {
    const kever = new Kever();
    kever.incept(
      makeIcpFields({
        bt: "2",
        b: [
          "BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8I",
          "BFOWfJGBBJDhsRxU1gwajMGnqTstbMwJ20YH21JFXHM4",
          "BBilc4-L3tFUnfM_wJr636TZGwB3BbRPSTkGDPMECFaXg",
        ],
      }),
    );

    kever.update(
      makeRotFields({
        bt: "2",
        br: ["BBilc4-L3tFUnfM_wJr636TZGwB3BbRPSTkGDPMECFaXg"],
        ba: ["BIKKuvBwpmDVA4Ds-wpbuoM77JRCagfyA2bMDnIF5GBc"],
      }),
    );

    expect(kever.witnesses).toEqual([
      "BGhCNcrRBR6mlBduhbuCYL7Bwc3gbuyaGo9opZsd0D8I",
      "BFOWfJGBBJDhsRxU1gwajMGnqTstbMwJ20YH21JFXHM4",
      "BIKKuvBwpmDVA4Ds-wpbuoM77JRCagfyA2bMDnIF5GBc",
    ]);
  });

  it("rejects rotation at sn > kever.sn + 1 (out of order)", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields());

    expect(() =>
      kever.update(makeRotFields({ s: "5" })),
    ).toThrow(SequenceError);
  });
});

describe("Kever.update — recovery rotation", () => {
  it("allows rot at sn > lastEst.s and <= kever.sn (recovery)", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields());

    // Apply 3 interactions
    kever.update(makeIxnFields({ s: "1", d: "EIXN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }));
    kever.update(
      makeIxnFields({
        s: "2",
        p: "EIXN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        d: "EIXN2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      }),
    );
    kever.update(
      makeIxnFields({
        s: "3",
        p: "EIXN2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        d: "EIXN3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      }),
    );
    expect(kever.sn).toBe(3);
    expect(kever.lastEst.s).toBe(0);

    // Recovery rotation at sn=1 (lastEst.s=0 < 1 <= 3=kever.sn)
    kever.update(
      makeRotFields({
        s: "1",
        p: "EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo",
      }),
    );
    expect(kever.sn).toBe(1);
    expect(kever.lastEst.s).toBe(1);
  });
});

describe("Kever.toKeyStateRecord", () => {
  it("exports a valid KeyStateRecord", () => {
    const kever = new Kever();
    kever.incept(makeIcpFields());

    const ksr = kever.toKeyStateRecord();
    expect(ksr.i).toBe("EBfxc4RiVY6saIFmUfEtbBkYFjCEEalUvkpbMQWMNCBo");
    expect(ksr.s).toBe("0");
    expect(ksr.k).toEqual(["DGBw9oJIm2eM-iHKGsLXFBKJwa4mRGHqtCrP69BO6O0g"]);
    expect(ksr.kt).toBe("1");
    expect(ksr.et).toBe("icp");
    expect(ksr.vn).toEqual([1, 0]);
    expect(ksr.ee.s).toBe("0");
    expect(ksr.di).toBe("");
  });
});
