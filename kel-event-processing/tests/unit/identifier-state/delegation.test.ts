import { describe, it, expect } from "vitest";
import { IdentifierState } from "../../../src/identifier-state.js";
import { ValidationError } from "../../../src/errors.js";
import { generateKeyPair } from "../../helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate N key pairs and return the qb64 verfer strings. */
async function makeKeys(n: number): Promise<string[]> {
  const keys: string[] = [];
  for (let i = 0; i < n; i++) {
    const kp = await generateKeyPair();
    keys.push(kp.verferQb64);
  }
  return keys;
}

/** Minimal delegated inception (dip) fields. */
function makeDipFields(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: "KERI10JSON000000_",
    t: "dip",
    d: "SAID_DIP_00000000000000000000000000000000000",
    i: "SAID_DIP_00000000000000000000000000000000000",
    s: "0",
    kt: "1",
    k: ["DKey111111111111111111111111111111111111111"],
    nt: "1",
    n: ["ENext11111111111111111111111111111111111111"],
    bt: "0",
    b: [],
    c: [],
    a: [],
    di: "EDelegator0000000000000000000000000000000000",
    ...overrides,
  };
}

/** Minimal delegated rotation (drt) fields. */
function makeDrtFields(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: "KERI10JSON000000_",
    t: "drt",
    d: "SAID_DRT_00000000000000000000000000000000000",
    i: "SAID_DIP_00000000000000000000000000000000000",
    s: "1",
    p: "SAID_DIP_00000000000000000000000000000000000",
    kt: "1",
    k: ["DKey222222222222222222222222222222222222222"],
    nt: "1",
    n: ["ENext22222222222222222222222222222222222222"],
    bt: "0",
    br: [],
    ba: [],
    a: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// D01: Delegated inception — valid
// ---------------------------------------------------------------------------

describe("Delegation — IdentifierState", () => {
  it("D01: delegatedInception_valid", () => {
    const delegatorPrefix = "EDelegator0000000000000000000000000000000000";
    const fields = makeDipFields({ di: delegatorPrefix });

    const state = IdentifierState.fromInception(fields);

    expect(state.isDelegated).toBe(true);
    expect(state.delegatorPrefix).toBe(delegatorPrefix);
    expect(state.prefix).toBe(fields.i);
    expect(state.sequenceNumber).toBe(0);
    expect(state.eventIlk).toBe("dip");
    expect(state.transferable).toBe(true);
    expect(state.signingKeys).toEqual(fields.k);
    expect(state.nextKeyDigests).toEqual(fields.n);
    expect(state.lastEstablishment).toEqual({ sn: 0, digest: fields.d });
  });

  // ---------------------------------------------------------------------------
  // D02: Delegated inception — verify state correctness
  // (Delegation seal validation is EventProcessor's responsibility,
  //  so we verify that IdentifierState correctly records delegation state.)
  // ---------------------------------------------------------------------------

  it("D02: delegatedInception_setsCorrectState", async () => {
    const [key] = await makeKeys(1);
    const [nextKey] = await makeKeys(1);
    const delegatorPrefix = "EDelegatorABC0000000000000000000000000000000";

    const fields = makeDipFields({
      k: [key],
      n: [nextKey],
      di: delegatorPrefix,
    });

    const state = IdentifierState.fromInception(fields);

    // Delegation state is correctly set
    expect(state.isDelegated).toBe(true);
    expect(state.delegatorPrefix).toBe(delegatorPrefix);

    // Key state is correctly set
    expect(state.signingKeys).toEqual([key]);
    expect(state.signingThreshold).toBe("1");
    expect(state.nextKeyDigests).toEqual([nextKey]);
    expect(state.nextThreshold).toBe("1");

    // Witness state
    expect(state.witnesses).toEqual([]);
    expect(state.witnessThreshold).toBe(0);

    // Snapshot round-trip preserves delegation fields
    const snap = state.snapshot();
    expect(snap.di).toBe(delegatorPrefix);
    expect(snap.et).toBe("dip");
  });

  // ---------------------------------------------------------------------------
  // D03: Delegated rotation — valid
  // ---------------------------------------------------------------------------

  it("D03: delegatedRotation_valid", async () => {
    const [key1] = await makeKeys(1);
    const [nextKey1] = await makeKeys(1);
    const [key2] = await makeKeys(1);
    const [nextKey2] = await makeKeys(1);
    const delegatorPrefix = "EDelegator0000000000000000000000000000000000";
    const dipSaid = "SAID_DIP_00000000000000000000000000000000000";

    // Create delegated identifier from dip
    const dipFields = makeDipFields({
      d: dipSaid,
      i: dipSaid,
      k: [key1],
      n: [nextKey1],
      di: delegatorPrefix,
    });
    const state = IdentifierState.fromInception(dipFields);

    // Apply delegated rotation
    const drtFields = makeDrtFields({
      i: dipSaid,
      s: "1",
      p: dipSaid,
      k: [key2],
      n: [nextKey2],
    });
    state.applyEvent(drtFields);

    // State is updated
    expect(state.sequenceNumber).toBe(1);
    expect(state.eventIlk).toBe("drt");
    expect(state.signingKeys).toEqual([key2]);
    expect(state.nextKeyDigests).toEqual([nextKey2]);
    expect(state.latestEventSaid).toBe(drtFields.d);
    expect(state.lastEstablishment).toEqual({ sn: 1, digest: drtFields.d });

    // Delegation state preserved
    expect(state.isDelegated).toBe(true);
    expect(state.delegatorPrefix).toBe(delegatorPrefix);
  });

  // ---------------------------------------------------------------------------
  // D04: Delegated rotation — missing approval (skip)
  // Delegation approval validation is EventProcessor's responsibility.
  // ---------------------------------------------------------------------------

  it.skip("D04: delegatedRotation_rejectMissingApproval — EventProcessor responsibility", () => {
    // Delegation approval checks (verifying the delegator's anchor seal)
    // are performed by the EventProcessor, not IdentifierState.
  });

  // ---------------------------------------------------------------------------
  // D05: Delegation — superseding rotation (recovery) with drt
  //
  // For DelegatedRotation, isValidSupersede allows lastEstSn <= sn <= keverSn,
  // meaning a drt can supersede at the same sn as the last establishment event.
  // ---------------------------------------------------------------------------

  it("D05: delegation_supersedingRotation", async () => {
    const [key1] = await makeKeys(1);
    const [nextKey1] = await makeKeys(1);
    const [key2] = await makeKeys(1);
    const [nextKey2] = await makeKeys(1);
    const [key3] = await makeKeys(1);
    const [nextKey3] = await makeKeys(1);
    const delegatorPrefix = "EDelegator0000000000000000000000000000000000";
    const dipSaid = "SAID_DIP_00000000000000000000000000000000000";

    // Step 1: Create delegated identifier at sn=0
    const dipFields = makeDipFields({
      d: dipSaid,
      i: dipSaid,
      k: [key1],
      n: [nextKey1],
      di: delegatorPrefix,
    });
    const state = IdentifierState.fromInception(dipFields);
    expect(state.sequenceNumber).toBe(0);
    expect(state.lastEstablishment.sn).toBe(0);

    // Step 2: Apply a normal drt at sn=1
    const drtSaid1 = "SAID_DRT1_0000000000000000000000000000000000";
    const drt1Fields = makeDrtFields({
      d: drtSaid1,
      i: dipSaid,
      s: "1",
      p: dipSaid,
      k: [key2],
      n: [nextKey2],
    });
    state.applyEvent(drt1Fields);
    expect(state.sequenceNumber).toBe(1);
    expect(state.lastEstablishment.sn).toBe(1);

    // Step 3: Apply an interaction event at sn=2 to advance the kever sn
    // beyond lastEst.sn so there's room for recovery.
    const ixnSaid = "SAID_IXN_00000000000000000000000000000000000";
    state.applyEvent({
      v: "KERI10JSON000000_",
      t: "ixn",
      d: ixnSaid,
      i: dipSaid,
      s: "2",
      p: drtSaid1,
      a: [],
    });
    expect(state.sequenceNumber).toBe(2);
    expect(state.lastEstablishment.sn).toBe(1);

    // Step 4: Superseding drt at sn=1 (recovery).
    // For drt, isValidSupersede requires: lastEstSn <= sn <= keverSn
    // Here: lastEstSn=1, sn=1, keverSn=2 → 1 <= 1 && 1 <= 2 → true.
    const recoverySaid = "SAID_RECOVERY_00000000000000000000000000000";
    const recoveryDrt = makeDrtFields({
      d: recoverySaid,
      i: dipSaid,
      s: "1",
      p: dipSaid, // points back to dip (the event before sn=1)
      k: [key3],
      n: [nextKey3],
    });

    // Should not throw — valid superseding rotation
    state.applyEvent(recoveryDrt);
    expect(state.sequenceNumber).toBe(1);
    expect(state.signingKeys).toEqual([key3]);
    expect(state.latestEventSaid).toBe(recoverySaid);
    expect(state.lastEstablishment).toEqual({ sn: 1, digest: recoverySaid });
  });

  // ---------------------------------------------------------------------------
  // D06: Superseding rules — rot cannot supersede at lastEstSn == sn
  //
  // For non-delegated Rotation, isValidSupersede requires lastEstSn < sn
  // (strictly less than), whereas drt allows lastEstSn <= sn.
  // This verifies the rot constraint is stricter.
  // ---------------------------------------------------------------------------

  it("D06: superseding_rotRejectsAtLastEstSn", async () => {
    const [key1] = await makeKeys(1);
    const [nextKey1] = await makeKeys(1);
    const [key2] = await makeKeys(1);
    const [nextKey2] = await makeKeys(1);
    const [key3] = await makeKeys(1);
    const [nextKey3] = await makeKeys(1);
    const icpSaid = "SAID_ICP_00000000000000000000000000000000000";

    // Create non-delegated identifier
    const state = IdentifierState.fromInception({
      v: "KERI10JSON000000_",
      t: "icp",
      d: icpSaid,
      i: icpSaid,
      s: "0",
      kt: "1",
      k: [key1],
      nt: "1",
      n: [nextKey1],
      bt: "0",
      b: [],
      c: [],
      a: [],
    });

    // Rotate at sn=1
    const rotSaid1 = "SAID_ROT1_0000000000000000000000000000000000";
    state.applyEvent({
      v: "KERI10JSON000000_",
      t: "rot",
      d: rotSaid1,
      i: icpSaid,
      s: "1",
      p: icpSaid,
      kt: "1",
      k: [key2],
      nt: "1",
      n: [nextKey2],
      bt: "0",
      br: [],
      ba: [],
      a: [],
    });
    expect(state.lastEstablishment.sn).toBe(1);

    // Interaction at sn=2 to advance keverSn
    state.applyEvent({
      v: "KERI10JSON000000_",
      t: "ixn",
      d: "SAID_IXN_00000000000000000000000000000000000",
      i: icpSaid,
      s: "2",
      p: rotSaid1,
      a: [],
    });
    expect(state.sequenceNumber).toBe(2);
    expect(state.lastEstablishment.sn).toBe(1);

    // Attempt superseding rot at sn=1, where lastEstSn=1.
    // For rot: isValidSupersede requires lastEstSn < sn, i.e. 1 < 1, which is false.
    // So this must be rejected.
    expect(() => {
      state.applyEvent({
        v: "KERI10JSON000000_",
        t: "rot",
        d: "SAID_RECOVERY_00000000000000000000000000000",
        i: icpSaid,
        s: "1",
        p: icpSaid,
        kt: "1",
        k: [key3],
        nt: "1",
        n: [nextKey3],
        bt: "0",
        br: [],
        ba: [],
        a: [],
      });
    }).toThrow(ValidationError);
  });

  // ---------------------------------------------------------------------------
  // D07: Superseding rules — drt allows supersede at lastEstSn == sn
  //
  // Complementary to D06: drt allows lastEstSn <= sn, so a delegated
  // rotation at sn equal to lastEstSn IS allowed.
  // ---------------------------------------------------------------------------

  it("D07: superseding_drtAllowsAtLastEstSn", async () => {
    const [key1] = await makeKeys(1);
    const [nextKey1] = await makeKeys(1);
    const [key2] = await makeKeys(1);
    const [nextKey2] = await makeKeys(1);
    const [key3] = await makeKeys(1);
    const [nextKey3] = await makeKeys(1);
    const dipSaid = "SAID_DIP_00000000000000000000000000000000000";
    const delegator = "EDelegator0000000000000000000000000000000000";

    // Create delegated identifier
    const state = IdentifierState.fromInception(makeDipFields({
      d: dipSaid,
      i: dipSaid,
      k: [key1],
      n: [nextKey1],
      di: delegator,
    }));

    // Delegated rotation at sn=1
    const drtSaid1 = "SAID_DRT1_0000000000000000000000000000000000";
    state.applyEvent(makeDrtFields({
      d: drtSaid1,
      i: dipSaid,
      s: "1",
      p: dipSaid,
      k: [key2],
      n: [nextKey2],
    }));
    expect(state.lastEstablishment.sn).toBe(1);

    // Interaction at sn=2 to advance keverSn beyond lastEst
    state.applyEvent({
      v: "KERI10JSON000000_",
      t: "ixn",
      d: "SAID_IXN_00000000000000000000000000000000000",
      i: dipSaid,
      s: "2",
      p: drtSaid1,
      a: [],
    });
    expect(state.sequenceNumber).toBe(2);
    expect(state.lastEstablishment.sn).toBe(1);

    // Superseding drt at sn=1 with lastEstSn=1.
    // For drt: lastEstSn <= sn && sn <= keverSn → 1 <= 1 && 1 <= 2 → true.
    const recoverySaid = "SAID_RECOV_000000000000000000000000000000000";
    state.applyEvent(makeDrtFields({
      d: recoverySaid,
      i: dipSaid,
      s: "1",
      p: dipSaid,
      k: [key3],
      n: [nextKey3],
    }));

    expect(state.sequenceNumber).toBe(1);
    expect(state.signingKeys).toEqual([key3]);
    expect(state.latestEventSaid).toBe(recoverySaid);
  });

  // ---------------------------------------------------------------------------
  // D08: Do Not Delegate reject — skip
  // DND trait enforcement is EventProcessor's responsibility.
  // ---------------------------------------------------------------------------

  it.skip("D08: delegation_doNotDelegateReject — EventProcessor responsibility", () => {
    // The DoNotDelegate (DND) trait prevents an identifier from acting as
    // a delegator. This is checked at the EventProcessor level when
    // processing delegation events, not by IdentifierState.
  });
});
