import { describe, it, expect } from "vitest";
import { IdentifierState } from "../../../src/identifier-state.js";
import { ValidationError } from "../../../src/errors.js";

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

/** Build interaction fields for use with applyEvent. */
function makeIxnFields(
  state: IdentifierState,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const sn = state.sequenceNumber + 1;
  const defaults: Record<string, unknown> = {
    t: "ixn",
    d: `EIXN_SAID_SN${sn}_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
    i: state.prefix,
    s: sn.toString(16),
    p: state.latestEventSaid,
    a: [],
  };
  return { ...defaults, ...overrides };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("IdentifierState.applyEvent — interaction", () => {
  it("X01: valid interaction increments sn, keys unchanged", () => {
    const state = makeInceptionState();
    const originalKeys = [...state.signingKeys];
    const originalThreshold = state.signingThreshold;
    const originalNextDigests = [...state.nextKeyDigests];
    const originalNextThreshold = state.nextThreshold;
    const originalWitnesses = [...state.witnesses];

    const ixnFields = makeIxnFields(state);
    state.applyEvent(ixnFields);

    expect(state.sequenceNumber).toBe(1);
    expect(state.eventIlk).toBe("ixn");
    expect(state.latestEventSaid).toBe(ixnFields.d);
    expect(state.signingKeys).toEqual(originalKeys);
    expect(state.signingThreshold).toBe(originalThreshold);
    expect(state.nextKeyDigests).toEqual(originalNextDigests);
    expect(state.nextThreshold).toBe(originalNextThreshold);
    expect(state.witnesses).toEqual(originalWitnesses);
  });

  it("X02: wrong prior throws ValidationError", () => {
    const state = makeInceptionState();
    const ixnFields = makeIxnFields(state, {
      p: "EWRONG_PRIOR_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });

    expect(() => state.applyEvent(ixnFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeIxnFields(makeInceptionState(), {
          p: "EWRONG_PRIOR_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }),
      ),
    ).toThrow(/Prior SAID mismatch/);
  });

  it("X03: non-sequential sn throws ValidationError", () => {
    const state = makeInceptionState();

    // sn=5 when expected sn=1
    const ixnFields = makeIxnFields(state, {
      s: "5",
    });

    expect(() => state.applyEvent(ixnFields)).toThrow(ValidationError);
  });

  it("X04: interaction with EO trait throws ValidationError", () => {
    const state = makeInceptionState({ c: ["EO"] });
    expect(state.isEstablishmentOnly).toBe(true);

    const ixnFields = makeIxnFields(state);

    expect(() => state.applyEvent(ixnFields)).toThrow(ValidationError);
    expect(() =>
      state.applyEvent(
        makeIxnFields(makeInceptionState({ c: ["EO"] })),
      ),
    ).toThrow(/EstablishmentOnly/);
  });

  it("X05: interaction with empty seals is valid", () => {
    const state = makeInceptionState();
    const ixnFields = makeIxnFields(state, { a: [] });

    state.applyEvent(ixnFields);

    expect(state.sequenceNumber).toBe(1);
    expect(state.eventIlk).toBe("ixn");
  });

  it("X06: interaction with multiple seals is valid", () => {
    const state = makeInceptionState();
    const ixnFields = makeIxnFields(state, {
      a: [
        { d: "EDigestSeal1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
        { i: "EPrefixSeal_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", s: "0", d: "ESealDigest" },
        { rd: "ERootSeal_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
      ],
    });

    state.applyEvent(ixnFields);

    expect(state.sequenceNumber).toBe(1);
    expect(state.eventIlk).toBe("ixn");
  });

  it("X07: keys, witnesses, and thresholds unchanged after interaction", () => {
    const witnesses = [
      "BWit1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "BWit2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    const state = makeInceptionState({
      kt: "1",
      k: [
        "DKey1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "DKey2_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ],
      bt: "1",
      b: witnesses,
      n: ["ENextDigest1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
    });

    const keysBefore = [...state.signingKeys];
    const thresholdBefore = state.signingThreshold;
    const witnessesBefore = [...state.witnesses];
    const witThresholdBefore = state.witnessThreshold;
    const nextDigestsBefore = [...state.nextKeyDigests];
    const nextThresholdBefore = state.nextThreshold;

    const ixnFields = makeIxnFields(state);
    state.applyEvent(ixnFields);

    expect(state.signingKeys).toEqual(keysBefore);
    expect(state.signingThreshold).toBe(thresholdBefore);
    expect(state.witnesses).toEqual(witnessesBefore);
    expect(state.witnessThreshold).toBe(witThresholdBefore);
    expect(state.nextKeyDigests).toEqual(nextDigestsBefore);
    expect(state.nextThreshold).toBe(nextThresholdBefore);

    // Also lastEstablishment should NOT change after interaction
    expect(state.lastEstablishment.sn).toBe(0);
  });

  it("multiple sequential interactions work correctly", () => {
    const state = makeInceptionState();

    // Interaction 1
    const ixn1 = makeIxnFields(state);
    state.applyEvent(ixn1);
    expect(state.sequenceNumber).toBe(1);

    // Interaction 2
    const ixn2 = makeIxnFields(state);
    state.applyEvent(ixn2);
    expect(state.sequenceNumber).toBe(2);

    // Interaction 3
    const ixn3 = makeIxnFields(state);
    state.applyEvent(ixn3);
    expect(state.sequenceNumber).toBe(3);

    // lastEstablishment should still point to inception
    expect(state.lastEstablishment.sn).toBe(0);
  });

  it("interaction after rotation uses correct prior SAID", () => {
    const state = makeInceptionState();

    // First do a rotation
    const rotFields: Record<string, unknown> = {
      t: "rot",
      d: "EROT_SAID_SN1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      i: state.prefix,
      s: "1",
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
    state.applyEvent(rotFields);
    expect(state.sequenceNumber).toBe(1);
    expect(state.latestEventSaid).toBe("EROT_SAID_SN1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    // Now interaction must use rot's SAID as prior
    const ixnFields = makeIxnFields(state);
    state.applyEvent(ixnFields);
    expect(state.sequenceNumber).toBe(2);
    expect(state.lastEstablishment.sn).toBe(1); // still points to rotation
  });
});
