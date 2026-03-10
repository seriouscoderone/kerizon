import { describe, it, expect } from "vitest";
import { IdentifierState } from "../../../src/identifier-state.js";
import { ValidationError } from "../../../src/errors.js";
import {
  generateKeyPair,
  encodeEd25519Verfer,
  buildKeriEvent,
} from "../../helpers.js";

// ── Helpers ─────────────────────────────────────────────────────────

/** Build inception event fields with defaults. */
function makeIcpFields(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const defaults: Record<string, unknown> = {
    t: "icp",
    d: "SAID_PLACEHOLDER",
    i: "SAID_PLACEHOLDER",
    s: "0",
    kt: "1",
    k: ["DFakeKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    nt: "1",
    n: ["EFakeDigest_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    bt: "0",
    b: [],
    c: [],
    a: [],
  };
  return { ...defaults, ...overrides };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("IdentifierState.fromInception", () => {
  it("I01: valid minimal inception — 1 key, no witnesses, with next keys", () => {
    const fields = makeIcpFields();
    const state = IdentifierState.fromInception(fields);

    expect(state.prefix).toBe("SAID_PLACEHOLDER");
    expect(state.sequenceNumber).toBe(0);
    expect(state.transferable).toBe(true);
    expect(state.signingKeys).toEqual(["DFakeKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
    expect(state.signingThreshold).toBe("1");
    expect(state.nextKeyDigests).toEqual(["EFakeDigest_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
    expect(state.nextThreshold).toBe("1");
    expect(state.witnesses).toEqual([]);
    expect(state.witnessThreshold).toBe(0);
    expect(state.isEstablishmentOnly).toBe(false);
    expect(state.isDoNotDelegate).toBe(false);
    expect(state.isDelegated).toBe(false);
    expect(state.eventIlk).toBe("icp");
    expect(state.latestEventSaid).toBe("SAID_PLACEHOLDER");
  });

  it("I02: full inception with witnesses, TOAD, multiple keys, config traits, seals", () => {
    const fields = makeIcpFields({
      kt: "2",
      k: [
        "DKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "DKey2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "DKey3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
      nt: "2",
      n: [
        "EDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "EDigest2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "EDigest3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
      bt: "2",
      b: [
        "BWitness1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BWitness2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BWitness3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
      c: ["EO", "DND"],
      a: [{ d: "EAnchorDigest1" }],
    });

    const state = IdentifierState.fromInception(fields);

    expect(state.signingKeys).toHaveLength(3);
    expect(state.signingThreshold).toBe("2");
    expect(state.nextKeyDigests).toHaveLength(3);
    expect(state.witnesses).toHaveLength(3);
    expect(state.witnessThreshold).toBe(2);
    expect(state.isEstablishmentOnly).toBe(true);
    expect(state.isDoNotDelegate).toBe(true);
    expect(state.transferable).toBe(true);
  });

  it("I03: sn != '0' throws ValidationError", () => {
    const fields = makeIcpFields({ s: "1" });
    expect(() => IdentifierState.fromInception(fields)).toThrow(ValidationError);
    expect(() => IdentifierState.fromInception(fields)).toThrow(
      "Inception event must have sn = 0",
    );
  });

  it("I04: empty keys [] throws ValidationError", () => {
    const fields = makeIcpFields({ k: [] });
    expect(() => IdentifierState.fromInception(fields)).toThrow(ValidationError);
    expect(() => IdentifierState.fromInception(fields)).toThrow(
      "At least one signing key is required",
    );
  });

  it("I05: kt='5' with 3 keys throws ValidationError", () => {
    const fields = makeIcpFields({
      kt: "5",
      k: [
        "DKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "DKey2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "DKey3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
    });
    expect(() => IdentifierState.fromInception(fields)).toThrow(ValidationError);
    expect(() => IdentifierState.fromInception(fields)).toThrow(
      /Signing threshold .* out of range/,
    );
  });

  it("I06: duplicate witnesses throws ValidationError", () => {
    const dup = "BWitness1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const fields = makeIcpFields({
      bt: "1",
      b: [dup, dup],
      n: ["EFakeDigest_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });
    expect(() => IdentifierState.fromInception(fields)).toThrow(ValidationError);
    expect(() => IdentifierState.fromInception(fields)).toThrow(
      "Duplicate witnesses",
    );
  });

  it("I07: bt > witness count throws ValidationError", () => {
    const fields = makeIcpFields({
      bt: "3",
      b: [
        "BWitness1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BWitness2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
      n: ["EFakeDigest_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });
    expect(() => IdentifierState.fromInception(fields)).toThrow(ValidationError);
    expect(() => IdentifierState.fromInception(fields)).toThrow(
      /TOAD .* out of range/,
    );
  });

  it("I08: bt='0' with witnesses present throws ValidationError (TOAD must be >= 1)", () => {
    // bt="0" parsed as parseInt("0",16)=0, witnesses.length=2>0, so TOAD 0 out of range [1,2]
    const fields = makeIcpFields({
      bt: "0",
      b: [
        "BWitness1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BWitness2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
      n: ["EFakeDigest_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });
    expect(() => IdentifierState.fromInception(fields)).toThrow(ValidationError);
    expect(() => IdentifierState.fromInception(fields)).toThrow(
      /TOAD .* out of range/,
    );
  });

  it("I09: non-transferable (n=[]) with witnesses throws ValidationError", () => {
    const fields = makeIcpFields({
      n: [],
      nt: "0",
      bt: "1",
      b: ["BWitness1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });
    expect(() => IdentifierState.fromInception(fields)).toThrow(ValidationError);
    expect(() => IdentifierState.fromInception(fields)).toThrow(
      "Non-transferable identifier must not have witnesses",
    );
  });

  it("I11: non-transferable (n=[]) with anchors throws ValidationError", () => {
    const fields = makeIcpFields({
      n: [],
      nt: "0",
      a: [{ d: "EAnchorDigest" }],
    });
    expect(() => IdentifierState.fromInception(fields)).toThrow(ValidationError);
    expect(() => IdentifierState.fromInception(fields)).toThrow(
      "Non-transferable identifier must not have anchors",
    );
  });

  it("I14: EO trait sets isEstablishmentOnly", () => {
    const fields = makeIcpFields({ c: ["EO"] });
    const state = IdentifierState.fromInception(fields);
    expect(state.isEstablishmentOnly).toBe(true);
    expect(state.isDoNotDelegate).toBe(false);
  });

  it("I15: DND trait sets isDoNotDelegate", () => {
    const fields = makeIcpFields({ c: ["DND"] });
    const state = IdentifierState.fromInception(fields);
    expect(state.isDoNotDelegate).toBe(true);
    expect(state.isEstablishmentOnly).toBe(false);
  });

  it("I16: weighted threshold [['1/2','1/2']] accepted in inception", () => {
    const fields = makeIcpFields({
      kt: [["1/2", "1/2"]],
      k: [
        "DKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "DKey2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
    });
    const state = IdentifierState.fromInception(fields);
    expect(state.signingThreshold).toEqual([["1/2", "1/2"]]);
    expect(state.signingKeys).toHaveLength(2);
  });

  it("I17: 3 keys with kt='2' sets all keys in state", () => {
    const keys = [
      "DKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "DKey2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "DKey3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    const fields = makeIcpFields({
      kt: "2",
      k: keys,
    });
    const state = IdentifierState.fromInception(fields);
    expect(state.signingKeys).toEqual(keys);
    expect(state.signingThreshold).toBe("2");
  });

  it("non-transferable with n=[] and no witnesses/anchors is valid", () => {
    const fields = makeIcpFields({
      n: [],
      nt: "0",
      bt: "0",
      b: [],
      a: [],
    });
    const state = IdentifierState.fromInception(fields);
    expect(state.transferable).toBe(false);
    expect(state.nextKeyDigests).toEqual([]);
  });

  it("delegated inception (dip) sets delegator fields", () => {
    const fields = makeIcpFields({
      t: "dip",
      di: "EDelegator_PREFIX_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    const state = IdentifierState.fromInception(fields);
    expect(state.isDelegated).toBe(true);
    expect(state.delegatorPrefix).toBe("EDelegator_PREFIX_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expect(state.eventIlk).toBe("dip");
  });

  it("lastEstablishment is set to sn=0 with SAID after inception", () => {
    const fields = makeIcpFields({ d: "ETEST_SAID_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" });
    // also set i to match since inception uses d as said
    fields.i = "ETEST_SAID_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    const state = IdentifierState.fromInception(fields);
    expect(state.lastEstablishment.sn).toBe(0);
    expect(state.lastEstablishment.digest).toBe("ETEST_SAID_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
  });
});
