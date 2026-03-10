import { describe, it, expect } from "vitest";
import { IdentifierState } from "../../../src/identifier-state.js";
import { ValidationError, OutOfOrderError } from "../../../src/errors.js";

// ── Helpers ─────────────────────────────────────────────────────────

/** Create a minimal valid inception state. */
function makeInceptionState(overrides: Record<string, unknown> = {}): IdentifierState {
  const defaults: Record<string, unknown> = {
    t: "icp",
    d: "EINCEPTION_SAID_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    i: "EINCEPTION_SAID_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    s: "0",
    kt: "1",
    k: ["DKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    nt: "1",
    n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    bt: "0",
    b: [],
    c: [],
    a: [],
  };
  return IdentifierState.fromInception({ ...defaults, ...overrides });
}

/** Build rotation fields for use with applyEvent. */
function makeRotFields(
  state: IdentifierState,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const sn = state.sequenceNumber + 1;
  const defaults: Record<string, unknown> = {
    t: "rot",
    d: `EROT_SAID_SN${sn}_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
    i: state.prefix,
    s: sn.toString(16),
    p: state.latestEventSaid,
    kt: "1",
    k: ["DNewKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    nt: "1",
    n: ["ENewNextDigest_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    bt: "0",
    br: [],
    ba: [],
    a: [],
  };
  return { ...defaults, ...overrides };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("IdentifierState.applyEvent — rotation", () => {
  it("R01: valid basic rotation updates state", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state);

    state.applyEvent(rotFields);

    expect(state.sequenceNumber).toBe(1);
    expect(state.signingKeys).toEqual(["DNewKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
    expect(state.nextKeyDigests).toEqual(["ENewNextDigest_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
    expect(state.eventIlk).toBe("rot");
    expect(state.latestEventSaid).toBe(rotFields.d);
    expect(state.lastEstablishment.sn).toBe(1);
    expect(state.lastEstablishment.digest).toBe(rotFields.d);
  });

  it("R02: wrong prior digest throws ValidationError", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state, {
      p: "EWRONG_PRIOR_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeRotFields(
          makeInceptionState(),
          { p: "EWRONG_PRIOR_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
        ),
      ),
    ).toThrow(/Prior SAID mismatch/);
  });

  it("R03: sn != current+1 (too high) throws OutOfOrderError", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state, {
      s: "5",
    });

    expect(() => state.applyEvent(rotFields)).toThrow(OutOfOrderError);
  });

  it("R04: rotate non-transferable identifier throws ValidationError", () => {
    const state = makeInceptionState({
      n: [],
      nt: "0",
    });
    // state.transferable = false because n=[]
    expect(state.transferable).toBe(false);

    const rotFields: Record<string, unknown> = {
      t: "rot",
      d: "EROT_SAID_SN1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      i: state.prefix,
      s: "1",
      p: state.latestEventSaid,
      kt: "1",
      k: ["DNewKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      nt: "0",
      n: [],
      bt: "0",
      br: [],
      ba: [],
      a: [],
    };

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() => state.applyEvent(rotFields)).toThrow(
      "Cannot rotate a non-transferable identifier",
    );
  });

  it("R05: new threshold > new keys throws ValidationError", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state, {
      kt: "5",
      k: ["DNewKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeRotFields(makeInceptionState(), {
          kt: "5",
          k: ["DNewKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        }),
      ),
    ).toThrow(/Signing threshold .* out of range/);
  });

  it("R06: add witnesses via ba", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state, {
      ba: [
        "BWitNew1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BWitNew2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
      bt: "1",
    });

    state.applyEvent(rotFields);

    expect(state.witnesses).toEqual([
      "BWitNew1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWitNew2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]);
    expect(state.witnessThreshold).toBe(1);
    expect(state.witnessAdds).toEqual([
      "BWitNew1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWitNew2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]);
  });

  it("R07: cut witnesses via br", () => {
    const witnesses = [
      "BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWit2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWit3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    const state = makeInceptionState({
      bt: "2",
      b: witnesses,
      n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });

    const rotFields = makeRotFields(state, {
      br: ["BWit2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      ba: [],
      bt: "1",
    });

    state.applyEvent(rotFields);

    expect(state.witnesses).toEqual([
      "BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWit3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]);
    expect(state.witnessCuts).toEqual([
      "BWit2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]);
  });

  it("R08: combined add and cut witnesses", () => {
    const witnesses = [
      "BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWit2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    const state = makeInceptionState({
      bt: "1",
      b: witnesses,
      n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });

    const rotFields = makeRotFields(state, {
      br: ["BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      ba: ["BWitNew_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      bt: "1",
    });

    state.applyEvent(rotFields);

    expect(state.witnesses).toEqual([
      "BWit2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWitNew_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]);
  });

  it("R09: duplicate in br throws ValidationError", () => {
    const witnesses = [
      "BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWit2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    const state = makeInceptionState({
      bt: "1",
      b: witnesses,
      n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });

    const dup = "BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const rotFields = makeRotFields(state, {
      br: [dup, dup],
      ba: [],
      bt: "1",
    });

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeRotFields(
          makeInceptionState({
            bt: "1",
            b: witnesses,
            n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
          }),
          { br: [dup, dup], ba: [], bt: "1" },
        ),
      ),
    ).toThrow(/Duplicate entries in witness removes/);
  });

  it("R10: duplicate in ba throws ValidationError", () => {
    const state = makeInceptionState();
    const dup = "BWitNew_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const rotFields = makeRotFields(state, {
      ba: [dup, dup],
      bt: "1",
    });

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeRotFields(makeInceptionState(), {
          ba: [dup, dup],
          bt: "1",
        }),
      ),
    ).toThrow(/Duplicate entries in witness adds/);
  });

  it("R11: remove witness not in current list throws ValidationError", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state, {
      br: ["BWitNonExistent_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      ba: [],
    });

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeRotFields(makeInceptionState(), {
          br: ["BWitNonExistent_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
          ba: [],
        }),
      ),
    ).toThrow(/not found in current witness list/);
  });

  it("R12: witness in both br and ba throws ValidationError", () => {
    const witnesses = [
      "BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    const state = makeInceptionState({
      bt: "1",
      b: witnesses,
      n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });

    const rotFields = makeRotFields(state, {
      br: ["BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      ba: ["BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      bt: "0",
    });

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeRotFields(
          makeInceptionState({
            bt: "1",
            b: witnesses,
            n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
          }),
          {
            br: ["BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            ba: ["BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            bt: "0",
          },
        ),
      ),
    ).toThrow(/appears in both removes.*and adds/);
  });

  it("R13: adding existing witness throws ValidationError", () => {
    const witnesses = [
      "BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    const state = makeInceptionState({
      bt: "1",
      b: witnesses,
      n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });

    const rotFields = makeRotFields(state, {
      br: [],
      ba: ["BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      bt: "1",
    });

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeRotFields(
          makeInceptionState({
            bt: "1",
            b: witnesses,
            n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
          }),
          {
            br: [],
            ba: ["BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            bt: "1",
          },
        ),
      ),
    ).toThrow(/already exists in current witness list/);
  });

  it("R14: TOAD update with new witness count — valid", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state, {
      ba: [
        "BWitNew1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BWitNew2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BWitNew3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
      bt: "2",
    });

    state.applyEvent(rotFields);
    expect(state.witnessThreshold).toBe(2);
    expect(state.witnesses).toHaveLength(3);
  });

  it("R15: TOAD > new witness count throws ValidationError", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state, {
      ba: ["BWitNew1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      bt: "5",
    });

    expect(() => state.applyEvent(rotFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeRotFields(makeInceptionState(), {
          ba: ["BWitNew1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
          bt: "5",
        }),
      ),
    ).toThrow(/TOAD .* out of range/);
  });

  it("R18: rotation with new keys changes signing keys", () => {
    const state = makeInceptionState();
    const newKeys = [
      "DRotKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "DRotKey2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    const rotFields = makeRotFields(state, {
      kt: "2",
      k: newKeys,
    });

    state.applyEvent(rotFields);

    expect(state.signingKeys).toEqual(newKeys);
    expect(state.signingThreshold).toBe("2");
  });

  it("R19: rotation with empty next digests makes identifier non-transferable", () => {
    const state = makeInceptionState();
    const rotFields = makeRotFields(state, {
      n: [],
      nt: "0",
    });

    state.applyEvent(rotFields);

    expect(state.transferable).toBe(false);
    expect(state.nextKeyDigests).toEqual([]);
  });

  it("R20: rotation with weighted threshold change", () => {
    const state = makeInceptionState({
      kt: "1",
      k: [
        "DKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "DKey2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
    });

    const rotFields = makeRotFields(state, {
      kt: [["1/2", "1/2"]],
      k: [
        "DNewKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "DNewKey2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
    });

    state.applyEvent(rotFields);

    expect(state.signingThreshold).toEqual([["1/2", "1/2"]]);
    expect(state.signingKeys).toHaveLength(2);
  });

  it("R21: multiple sequential rotations work correctly", () => {
    const state = makeInceptionState();

    // Rotation 1
    const rot1Fields = makeRotFields(state);
    state.applyEvent(rot1Fields);
    expect(state.sequenceNumber).toBe(1);

    // Rotation 2
    const rot2Fields = makeRotFields(state, {
      d: "EROT_SAID_SN2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      k: ["DKeyRot2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
      n: ["EDigRot3_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });
    state.applyEvent(rot2Fields);
    expect(state.sequenceNumber).toBe(2);
    expect(state.signingKeys).toEqual(["DKeyRot2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
    expect(state.lastEstablishment.sn).toBe(2);
  });
});
