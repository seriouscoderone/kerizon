import { describe, it, expect } from "vitest";
import { KeyStateView } from "../../../src/views/key-state.js";
import { BuiltEvent } from "../../../src/builders/signed-event.js";
import type { Signer } from "../../../src/builders/signed-event.js";
import { EscrowReason } from "../../../src/views/pending-event.js";
import type { PendingEvent } from "../../../src/views/pending-event.js";
import type { KeyStateSnapshot } from "../../../src/types.js";
import { InceptionBuilder } from "../../../src/builders/inception.js";
import { testHashFn, generateKeyPair, signMessage } from "../../helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a complete KeyStateSnapshot for testing. */
function makeSnapshot(overrides: Partial<KeyStateSnapshot> = {}): KeyStateSnapshot {
  return {
    vn: [1, 0],
    i: "EExampleId00000000000000000000000000000000000",
    s: "5",
    p: "EPriorSaid0000000000000000000000000000000000",
    d: "ELatestSaid000000000000000000000000000000000",
    f: "a",
    dt: "2026-03-10T12:00:00.000000+00:00",
    et: "rot",
    kt: "2",
    k: [
      "DKey1000000000000000000000000000000000000000",
      "DKey2000000000000000000000000000000000000000",
      "DKey3000000000000000000000000000000000000000",
    ],
    nt: "1",
    n: [
      "ENext100000000000000000000000000000000000000",
      "ENext200000000000000000000000000000000000000",
    ],
    bt: "2",
    b: [
      "BWit1000000000000000000000000000000000000000",
      "BWit2000000000000000000000000000000000000000",
      "BWit3000000000000000000000000000000000000000",
    ],
    c: ["EO", "DND"],
    ee: { s: "3", d: "EEstSaid0000000000000000000000000000000000", br: [], ba: [] },
    di: "EDelegator00000000000000000000000000000000000",
    ...overrides,
  };
}

/** Create a mock Signer that uses Ed25519 crypto.subtle. */
async function makeSigner(index: number, ondex?: number): Promise<Signer & { publicKeyBytes: Uint8Array }> {
  const kp = await generateKeyPair();
  return {
    index,
    ondex,
    publicKeyBytes: kp.publicKeyBytes,
    async sign(message: Uint8Array): Promise<Uint8Array> {
      return signMessage(kp.privateKey, message);
    },
  };
}

// ---------------------------------------------------------------------------
// SV01–SV02: BuiltEvent.signWith
// ---------------------------------------------------------------------------

describe("BuiltEvent.signWith", () => {
  it("SV01: signWith single signer populates sigers with correct index", async () => {
    const kp = await generateKeyPair();
    const event = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .build();

    const signer = await makeSigner(0);
    await event.signWith([signer]);

    expect(event.sigers).toHaveLength(1);
    expect(event.sigers[0].index).toBe(0);
    // Raw signature should be 64 bytes for Ed25519
    expect(event.sigers[0].raw).toBeInstanceOf(Uint8Array);
    expect(event.sigers[0].raw.length).toBe(64);
    // qb64 should be a non-empty string
    expect(event.sigers[0].qb64).toBeTruthy();
    expect(typeof event.sigers[0].qb64).toBe("string");
  });

  it("SV02: signWith multiple signers populates 3 sigers", async () => {
    const keys = [];
    for (let i = 0; i < 3; i++) {
      const kp = await generateKeyPair();
      keys.push(kp.verferQb64);
    }

    const event = new InceptionBuilder(testHashFn)
      .signingKeys(keys)
      .build();

    const signers = [
      await makeSigner(0),
      await makeSigner(1),
      await makeSigner(2),
    ];
    await event.signWith(signers);

    expect(event.sigers).toHaveLength(3);
    expect(event.sigers[0].index).toBe(0);
    expect(event.sigers[1].index).toBe(1);
    expect(event.sigers[2].index).toBe(2);

    // Each signature should be 64 bytes
    for (const siger of event.sigers) {
      expect(siger.raw.length).toBe(64);
    }
  });
});

// ---------------------------------------------------------------------------
// SV03–SV07: KeyStateView property mapping
// ---------------------------------------------------------------------------

describe("KeyStateView", () => {
  it("SV03: from snapshot all properties map correctly", () => {
    const snapshot = makeSnapshot();
    const view = new KeyStateView(snapshot);

    expect(view.identifier).toBe(snapshot.i);
    expect(view.sequenceNumber).toBe(parseInt(snapshot.s, 16));
    expect(view.latestEventSaid).toBe(snapshot.d);
    expect(view.priorEventSaid).toBe(snapshot.p);
    expect(view.firstSeenOrdinal).toBe(parseInt(snapshot.f, 16));
    expect(view.firstSeenDatetime).toBe(snapshot.dt);
    expect(view.latestEventType).toBe(snapshot.et);
    expect(view.delegator).toBe(snapshot.di);
    expect(view.protocolVersion).toEqual(snapshot.vn);
    expect(view.configTraits).toEqual(snapshot.c);
    expect(view.lastEstablishmentSn).toBe(parseInt(snapshot.ee.s, 16));
    expect(view.lastEstablishmentSaid).toBe(snapshot.ee.d);
    expect(view.toSnapshot()).toBe(snapshot);
  });

  it("SV04: signingKeys maps to k, signingThreshold maps to kt", () => {
    const snapshot = makeSnapshot({ kt: "2", k: ["DKeyA", "DKeyB"] });
    const view = new KeyStateView(snapshot);

    expect(view.signingKeys).toEqual(["DKeyA", "DKeyB"]);
    expect(view.signingThreshold).toBe("2");
  });

  it("SV04 (weighted): weighted threshold preserved", () => {
    const snapshot = makeSnapshot({ kt: [["1/2", "1/2", "1/2"]] });
    const view = new KeyStateView(snapshot);
    expect(view.signingThreshold).toEqual([["1/2", "1/2", "1/2"]]);
  });

  it("SV05: nextKeyDigests maps to n, nextKeyThreshold maps to nt", () => {
    const snapshot = makeSnapshot({
      nt: "1",
      n: ["ENextA000", "ENextB000"],
    });
    const view = new KeyStateView(snapshot);

    expect(view.nextKeyDigests).toEqual(["ENextA000", "ENextB000"]);
    expect(view.nextKeyThreshold).toBe("1");
  });

  it("SV06: witnesses maps to b, witnessThreshold maps to bt (parsed as hex)", () => {
    const snapshot = makeSnapshot({
      bt: "a",   // hex a = decimal 10
      b: ["BWitA", "BWitB"],
    });
    const view = new KeyStateView(snapshot);

    expect(view.witnesses).toEqual(["BWitA", "BWitB"]);
    expect(view.witnessThreshold).toBe(10);
  });

  it("SV07: isTransferable, isDelegated, isEstablishmentOnly, isDoNotDelegate", () => {
    // Full case: transferable, delegated, EO, DND
    const fullSnapshot = makeSnapshot({
      n: ["ENext1"],
      di: "EDelegator",
      c: ["EO", "DND"],
    });
    const fullView = new KeyStateView(fullSnapshot);
    expect(fullView.isTransferable).toBe(true);
    expect(fullView.isDelegated).toBe(true);
    expect(fullView.isEstablishmentOnly).toBe(true);
    expect(fullView.isDoNotDelegate).toBe(true);

    // Minimal case: non-transferable, not delegated, no traits
    const minSnapshot = makeSnapshot({
      n: [],
      di: "",
      c: [],
    });
    const minView = new KeyStateView(minSnapshot);
    expect(minView.isTransferable).toBe(false);
    expect(minView.isDelegated).toBe(false);
    expect(minView.isEstablishmentOnly).toBe(false);
    expect(minView.isDoNotDelegate).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SV08–SV09: prepareRotation / prepareInteraction
// ---------------------------------------------------------------------------

describe("KeyStateView preparation helpers", () => {
  it("SV08: prepareRotation returns correct fields", () => {
    const snapshot = makeSnapshot({
      i: "ERotId00000000000000000000000000000000000000",
      s: "3",   // hex 3
      d: "ERotSaid000000000000000000000000000000000000",
      b: ["BWitX", "BWitY"],
    });
    const view = new KeyStateView(snapshot);

    const prep = view.prepareRotation();
    expect(prep.identifier).toBe("ERotId00000000000000000000000000000000000000");
    expect(prep.previousEvent).toBe("ERotSaid000000000000000000000000000000000000");
    expect(prep.sequenceNumber).toBe(4);  // 3 + 1
    expect(prep.witnesses).toEqual(["BWitX", "BWitY"]);
    // Witnesses should be a copy, not a reference
    expect(prep.witnesses).not.toBe(snapshot.b);
  });

  it("SV09: prepareInteraction returns correct fields", () => {
    const snapshot = makeSnapshot({
      i: "EIxnId0000000000000000000000000000000000000",
      s: "f",    // hex f = decimal 15
      d: "EIxnSaid00000000000000000000000000000000000",
    });
    const view = new KeyStateView(snapshot);

    const prep = view.prepareInteraction();
    expect(prep.identifier).toBe("EIxnId0000000000000000000000000000000000000");
    expect(prep.previousEvent).toBe("EIxnSaid00000000000000000000000000000000000");
    expect(prep.sequenceNumber).toBe(16);  // 15 + 1
  });
});

// ---------------------------------------------------------------------------
// SV10: Fluent chain test
// ---------------------------------------------------------------------------

describe("KeyStateView fluent usage", () => {
  it("SV10: view can be used to prepare rotation then interaction in chain", () => {
    const snapshot = makeSnapshot({
      i: "EFluentId000000000000000000000000000000000000",
      s: "1",
      d: "EFluentSaid00000000000000000000000000000000000",
      b: ["BWit1"],
    });

    const view = new KeyStateView(snapshot);

    // Both helpers can be called in sequence without error
    const rotPrep = view.prepareRotation();
    const ixnPrep = view.prepareInteraction();

    expect(rotPrep.identifier).toBe(ixnPrep.identifier);
    expect(rotPrep.previousEvent).toBe(ixnPrep.previousEvent);
    expect(rotPrep.sequenceNumber).toBe(ixnPrep.sequenceNumber);

    // The original view should be unchanged
    expect(view.sequenceNumber).toBe(1);
    expect(view.latestEventSaid).toBe("EFluentSaid00000000000000000000000000000000000");
  });
});

// ---------------------------------------------------------------------------
// SV11–SV13: PendingEvent view tests (simplified since it is an interface)
// ---------------------------------------------------------------------------

describe("PendingEvent", () => {
  it("SV11: PendingEvent structure has expected fields", () => {
    const pending: PendingEvent = {
      event: new Uint8Array([1, 2, 3]),
      prefix: "EPendId000000000000000000000000000000000000",
      sn: 4,
      said: "EPendSaid00000000000000000000000000000000000",
      reason: EscrowReason.PARTIAL_SIGNATURES,
      escrowedAt: Date.now(),
      signaturesCollected: 1,
      signaturesNeeded: 2,
      witnessesCollected: 0,
      witnessesNeeded: 3,
      isExpired: false,
    };

    expect(pending.prefix).toBe("EPendId000000000000000000000000000000000000");
    expect(pending.sn).toBe(4);
    expect(pending.reason).toBe(EscrowReason.PARTIAL_SIGNATURES);
    expect(pending.isExpired).toBe(false);
  });

  it("SV12: EscrowReason enum values", () => {
    expect(EscrowReason.PARTIAL_SIGNATURES).toBe("partial_signatures");
    expect(EscrowReason.PARTIAL_WITNESSES).toBe("partial_witnesses");
    expect(EscrowReason.OUT_OF_ORDER).toBe("out_of_order");
    expect(EscrowReason.LIKELY_DUPLICITOUS).toBe("likely_duplicitous");
    expect(EscrowReason.PENDING_DELEGATION).toBe("pending_delegation");
    expect(EscrowReason.DELEGABLE).toBe("delegable");
    expect(EscrowReason.MISFIT_SOURCE).toBe("misfit_source");
    expect(EscrowReason.UNVERIFIED_WITNESS_RECEIPT).toBe("unverified_witness_receipt");
    expect(EscrowReason.UNVERIFIED_RECEIPT).toBe("unverified_receipt");
    expect(EscrowReason.UNVERIFIED_TRANSFERABLE_RECEIPT).toBe("unverified_transferable_receipt");
  });

  it("SV13: PendingEvent with expired flag", () => {
    const pending: PendingEvent = {
      event: new Uint8Array([]),
      prefix: "EExpiredId0000000000000000000000000000000000",
      sn: 1,
      said: "EExpiredSaid000000000000000000000000000000000",
      reason: EscrowReason.OUT_OF_ORDER,
      escrowedAt: Date.now() - 86_400_000,
      signaturesCollected: 0,
      signaturesNeeded: 1,
      witnessesCollected: 0,
      witnessesNeeded: 0,
      isExpired: true,
    };

    expect(pending.isExpired).toBe(true);
    expect(pending.reason).toBe(EscrowReason.OUT_OF_ORDER);
  });
});
