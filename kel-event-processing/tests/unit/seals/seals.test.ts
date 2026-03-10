import { describe, it, expect } from "vitest";
import {
  EventSeal,
  DigestSeal,
  RootSeal,
  SourceSeal,
  LastEstSeal,
  BackerSeal,
  KindSeal,
} from "../../../src/builders/seals.js";
import { InceptionBuilder } from "../../../src/builders/inception.js";
import { testHashFn, generateKeyPair } from "../../helpers.js";

// ---------------------------------------------------------------------------
// SB01–SB07: Individual seal factories
// ---------------------------------------------------------------------------

describe("Seal factories", () => {
  it("SB01: EventSeal.of produces {i, s, d}", () => {
    const seal = EventSeal.of(
      "EEventId0000000000000000000000000000000000000",
      3,
      "EEventDigest000000000000000000000000000000000",
    );

    expect(seal).toEqual({
      i: "EEventId0000000000000000000000000000000000000",
      s: "3",
      d: "EEventDigest000000000000000000000000000000000",
    });
  });

  it("SB01 (supplemental): EventSeal.of encodes sn as hex", () => {
    const seal = EventSeal.of("Eabc", 255, "Edef");
    expect(seal.s).toBe("ff");
  });

  it("SB02: DigestSeal.of produces {d}", () => {
    const seal = DigestSeal.of("EDigest000000000000000000000000000000000000");
    expect(seal).toEqual({
      d: "EDigest000000000000000000000000000000000000",
    });
  });

  it("SB03: RootSeal.of produces {rd}", () => {
    const seal = RootSeal.of("ERootDigest0000000000000000000000000000000");
    expect(seal).toEqual({
      rd: "ERootDigest0000000000000000000000000000000",
    });
  });

  it("SB04: SourceSeal.of produces {s, d}", () => {
    const seal = SourceSeal.of(5, "ESourceDigest000000000000000000000000000000");
    expect(seal).toEqual({
      s: "5",
      d: "ESourceDigest000000000000000000000000000000",
    });
  });

  it("SB04 (supplemental): SourceSeal.of encodes sn as hex", () => {
    const seal = SourceSeal.of(16, "Edig");
    expect(seal.s).toBe("10");
  });

  it("SB05: LastEstSeal.of produces {i}", () => {
    const seal = LastEstSeal.of("ELastEstId00000000000000000000000000000000");
    expect(seal).toEqual({
      i: "ELastEstId00000000000000000000000000000000",
    });
  });

  it("SB06: BackerSeal.of produces {bi, d}", () => {
    const seal = BackerSeal.of(
      "BBackerPrefix0000000000000000000000000000000",
      "EBackerDigest0000000000000000000000000000000",
    );
    expect(seal).toEqual({
      bi: "BBackerPrefix0000000000000000000000000000000",
      d: "EBackerDigest0000000000000000000000000000000",
    });
  });

  it("SB07: KindSeal.of produces {t, d}", () => {
    const seal = KindSeal.of("KERI10JSON000000_", "EKindDigest00000000000000000000000000000000");
    expect(seal).toEqual({
      t: "KERI10JSON000000_",
      d: "EKindDigest00000000000000000000000000000000",
    });
  });
});

// ---------------------------------------------------------------------------
// SB08: Composability — multiple seal types in anchoredSeals
// ---------------------------------------------------------------------------

describe("Seal composability", () => {
  it("SB08: multiple seal types preserved in `a` field", async () => {
    const kp = await generateKeyPair();

    const eventSeal = EventSeal.of("ESealId000", 1, "ESealD000");
    const digestSeal = DigestSeal.of("EDigSeal000");
    const rootSeal = RootSeal.of("ERootSeal000");
    const sourceSeal = SourceSeal.of(2, "ESrcSeal000");
    const lastEstSeal = LastEstSeal.of("EEstSeal000");
    const backerSeal = BackerSeal.of("BBkr000", "EBkrD000");
    const kindSeal = KindSeal.of("KERI10JSON000000_", "EKndD000");

    const allSeals = [
      eventSeal,
      digestSeal,
      rootSeal,
      sourceSeal,
      lastEstSeal,
      backerSeal,
      kindSeal,
    ];

    const event = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .anchoredSeals(allSeals)
      .build();

    const anchors = event.fields.a as object[];
    expect(anchors).toHaveLength(7);

    // Verify each seal is preserved in order
    expect(anchors[0]).toEqual(eventSeal);
    expect(anchors[1]).toEqual(digestSeal);
    expect(anchors[2]).toEqual(rootSeal);
    expect(anchors[3]).toEqual(sourceSeal);
    expect(anchors[4]).toEqual(lastEstSeal);
    expect(anchors[5]).toEqual(backerSeal);
    expect(anchors[6]).toEqual(kindSeal);
  });
});
