import { describe, it, expect } from "vitest";
import {
  parseVersionString,
  validateStructure,
} from "../../../src/core/events/validateStructure.js";
import { computeSaid, buildEventWithVersion } from "../../../src/core/events/computeSaid.js";
import { StructuralError } from "../../../src/types/errors.js";
import type { HashFn } from "cesr-ts";

/** Synchronous SHA-256 placeholder — uses a simple dummy for structural tests. */
function dummyHash(data: Uint8Array): Uint8Array {
  // For structural tests that don't need real SAID binding, return deterministic bytes
  // based on data length. Real SAID tests will use actual crypto.
  const hash = new Uint8Array(32);
  for (let i = 0; i < data.length && i < 32; i++) {
    hash[i] = data[i] ^ 0x42;
  }
  return hash;
}

const testHash: HashFn = dummyHash;

describe("parseVersionString", () => {
  it("parses a valid v1.0 JSON version string", () => {
    const v = parseVersionString("KERI10JSON000120_");
    expect(v.protocol).toBe("KERI");
    expect(v.major).toBe(1);
    expect(v.minor).toBe(0);
    expect(v.kind).toBe("JSON");
    expect(v.size).toBe(0x120);
  });

  it("rejects wrong length", () => {
    expect(() => parseVersionString("KERI10JSON00012_")).toThrow(StructuralError);
  });

  it("rejects wrong terminator", () => {
    expect(() => parseVersionString("KERI10JSON000120.")).toThrow(StructuralError);
  });

  it("rejects unknown protocol", () => {
    expect(() => parseVersionString("ACDC10JSON000120_")).toThrow(StructuralError);
  });

  it("rejects unknown kind", () => {
    expect(() => parseVersionString("KERI10YAML000120_")).toThrow(StructuralError);
  });
});

describe("validateStructure", () => {
  it("validates a well-formed inception event (field order only)", () => {
    const fields = buildEventWithVersion({
      t: "icp",
      d: "E" + "A".repeat(43),
      i: "E" + "A".repeat(43),
      s: "0",
      kt: "1",
      k: ["DGBw9oJIm2eM-iHKGsLXFBKJwa4mRGHqtCrP69BO6O0g"],
      nt: "1",
      n: ["EMQQx1qz-HCuHMsCHJK5bnkAt-oq6jGpivdPazusJvas"],
      bt: "0",
      b: [],
      c: [],
      a: [],
    });
    // Without hashFn, only checks field order (not SAID binding)
    validateStructure(fields);
  });

  it("validates inception with SAID binding", () => {
    const fields = buildEventWithVersion({
      t: "icp",
      d: "",
      i: "",
      s: "0",
      kt: "1",
      k: ["DGBw9oJIm2eM-iHKGsLXFBKJwa4mRGHqtCrP69BO6O0g"],
      nt: "1",
      n: ["EMQQx1qz-HCuHMsCHJK5bnkAt-oq6jGpivdPazusJvas"],
      bt: "0",
      b: [],
      c: [],
      a: [],
    });
    const { fields: withSaid, raw } = computeSaid(fields, testHash);
    // Should not throw — SAID binding with same hash should pass
    validateStructure(withSaid, testHash, raw);
  });

  it("rejects missing type field", () => {
    expect(() =>
      validateStructure({ v: "KERI10JSON000020_" }),
    ).toThrow(StructuralError);
  });

  it("rejects unknown ilk", () => {
    expect(() =>
      validateStructure({ v: "KERI10JSON000020_", t: "xyz" }),
    ).toThrow(StructuralError);
  });

  it("rejects wrong field count", () => {
    expect(() =>
      validateStructure({
        v: "KERI10JSON000020_",
        t: "ixn",
        d: "",
        i: "",
        s: "0",
        p: "",
        a: [],
        extra: "bad",
      }),
    ).toThrow(StructuralError);
  });

  it("rejects wrong field order", () => {
    expect(() =>
      validateStructure({
        v: "KERI10JSON000020_",
        t: "ixn",
        i: "",
        d: "",
        s: "0",
        p: "",
        a: [],
      }),
    ).toThrow(StructuralError);
  });
});
