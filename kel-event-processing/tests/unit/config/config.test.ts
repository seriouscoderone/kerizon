import { describe, it, expect } from "vitest";
import { EventProcessor } from "../../../src/event-processor.js";
import { DomainEventBus } from "../../../src/domain-events.js";
import { InMemoryEventRepository, DefaultCryptoProvider } from "../../../src/repository/memory.js";
import { InceptionBuilder } from "../../../src/builders/inception.js";
import { InteractionBuilder } from "../../../src/builders/interaction.js";
import { IdentifierState } from "../../../src/identifier-state.js";
import { ValidationError } from "../../../src/errors.js";
import { DEFAULT_PROCESSOR_CONFIG } from "../../../src/config.js";
import { generateKeyPair, signMessage, testHashFn } from "../../helpers.js";
import { encodeEd25519IndexedSig } from "../../helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeProcessor(config?: Record<string, unknown>) {
  const repo = new InMemoryEventRepository();
  const bus = new DomainEventBus();
  const crypto = new DefaultCryptoProvider();
  const processor = new EventProcessor(repo, bus, crypto, config as any);
  return { repo, bus, crypto, processor };
}

async function buildSignedInception(opts?: { nextKeys?: boolean; traits?: string[] }) {
  const kp1 = await generateKeyPair();
  const kp2 = opts?.nextKeys !== false ? await generateKeyPair() : undefined;

  let builder = new InceptionBuilder(testHashFn)
    .signingKeys([kp1.verferQb64]);

  if (kp2) {
    builder = builder.nextKeys([kp2.verferQb64]);
  }

  const icp = builder.build();

  const sigBytes = await signMessage(kp1.privateKey, icp.raw);
  const qb64 = encodeEd25519IndexedSig(sigBytes, 0);
  const siger = { index: 0, raw: sigBytes, qb64 };

  return { icp, siger, kp1, kp2 };
}

async function buildSignedInceptionWithTraits(traits: { eo?: boolean; dnd?: boolean }) {
  const kp1 = await generateKeyPair();
  const kp2 = await generateKeyPair();

  let builder = new InceptionBuilder(testHashFn)
    .signingKeys([kp1.verferQb64])
    .nextKeys([kp2.verferQb64]);

  if (traits.eo) builder = builder.establishmentOnly();
  if (traits.dnd) builder = builder.doNotDelegate();

  const icp = builder.build();

  const sigBytes = await signMessage(kp1.privateKey, icp.raw);
  const qb64 = encodeEd25519IndexedSig(sigBytes, 0);
  const siger = { index: 0, raw: sigBytes, qb64 };

  return { icp, siger, kp1, kp2 };
}

// ---------------------------------------------------------------------------
// C01: promiscuous=true -> accepts events for any AID
// ---------------------------------------------------------------------------

describe("ProcessorConfig", () => {
  it("C01: promiscuous=true (default) -> accepts events for any AID", async () => {
    const { processor, bus } = makeProcessor({ promiscuous: true });

    // Ingest two different AIDs
    const { icp: icp1, siger: sig1 } = await buildSignedInception();
    const { icp: icp2, siger: sig2 } = await buildSignedInception();

    await processor.ingestEvent({ raw: icp1.raw, fields: icp1.fields }, [sig1]);
    await processor.ingestEvent({ raw: icp2.raw, fields: icp2.fields }, [sig2]);

    // Both should be accepted
    const events = bus.drain();
    const accepted = events.filter((e) => e.type === "EventAccepted");
    expect(accepted).toHaveLength(2);

    // Both AIDs should be tracked
    expect(processor.identifiers.size).toBe(2);
  });

  // ---------------------------------------------------------------------------
  // C02: promiscuous=false -> behavior check
  // ---------------------------------------------------------------------------

  it("C02: promiscuous=false -> EventProcessor does not implement AID filtering", async () => {
    // The current EventProcessor does not read config.promiscuous to filter AIDs.
    // It processes any incoming inception regardless. This test documents that behavior.
    const { processor, bus } = makeProcessor({ promiscuous: false });

    const { icp, siger } = await buildSignedInception();
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [siger]);

    // Still accepted (promiscuous filtering not yet implemented)
    const events = bus.drain();
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].type).toBe("EventAccepted");
  });

  // ---------------------------------------------------------------------------
  // C03: defaultLocal config
  // ---------------------------------------------------------------------------

  it("C03: defaultLocal config affects provenance storage", async () => {
    const { processor, repo } = makeProcessor({ defaultLocal: true });

    const { icp, siger } = await buildSignedInception();
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [siger]);

    // Event was stored with local=true provenance
    const prefix = icp.fields.i as string;
    const said = icp.fields.d as string;
    const provenance = await repo.retrieveProvenance(prefix, said);
    expect(provenance).toBeDefined();
    expect(provenance!.local).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // C04: defaultLocal=false -> remote provenance
  // ---------------------------------------------------------------------------

  it("C04: defaultLocal=false -> remote provenance", async () => {
    const { processor, repo } = makeProcessor({ defaultLocal: false });

    const { icp, siger } = await buildSignedInception();
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [siger]);

    const prefix = icp.fields.i as string;
    const said = icp.fields.d as string;
    const provenance = await repo.retrieveProvenance(prefix, said);
    expect(provenance).toBeDefined();
    expect(provenance!.local).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // C05: local option override on ingestEvent
  // ---------------------------------------------------------------------------

  it("C05: ingestEvent local option overrides defaultLocal", async () => {
    const { processor, repo } = makeProcessor({ defaultLocal: false });

    const { icp, siger } = await buildSignedInception();
    await processor.ingestEvent(
      { raw: icp.raw, fields: icp.fields },
      [siger],
      { local: true },
    );

    const prefix = icp.fields.i as string;
    const said = icp.fields.d as string;
    const provenance = await repo.retrieveProvenance(prefix, said);
    expect(provenance).toBeDefined();
    expect(provenance!.local).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // C06: directMode=true -> EventAccepted events produced
  // ---------------------------------------------------------------------------

  it("C06: directMode=true -> EventAccepted events produced", async () => {
    const { processor, bus } = makeProcessor({ directMode: true });

    const { icp, siger } = await buildSignedInception();
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [siger]);

    const events = bus.drain();
    const accepted = events.filter((e) => e.type === "EventAccepted");
    const noticed = events.filter((e) => e.type === "EventNoticed");
    expect(accepted.length).toBeGreaterThanOrEqual(1);
    expect(noticed).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // C07: directMode=false -> EventNoticed events produced
  // ---------------------------------------------------------------------------

  it("C07: directMode=false -> EventNoticed events produced", async () => {
    const { processor, bus } = makeProcessor({ directMode: false });

    const { icp, siger } = await buildSignedInception();
    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [siger]);

    const events = bus.drain();
    const noticed = events.filter((e) => e.type === "EventNoticed");
    const accepted = events.filter((e) => e.type === "EventAccepted");
    expect(noticed.length).toBeGreaterThanOrEqual(1);
    expect(accepted).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // C08: readOnly=true -> FEL still written but first-seen log skips store
  // ---------------------------------------------------------------------------

  it("C08: readOnly=true -> commitEvent uses provided ordinal, skips FEL store", async () => {
    const { processor, repo, bus } = makeProcessor({ readOnly: true });

    const { icp, siger } = await buildSignedInception();
    await processor.ingestEvent(
      { raw: icp.raw, fields: icp.fields },
      [siger],
      { firstSeenOrdinal: 99, firstSeenDatetime: "2026-01-01T00:00:00Z" },
    );

    // Event should still be accepted
    const events = bus.drain();
    expect(events.length).toBeGreaterThanOrEqual(1);

    // The state should reflect the provided ordinal
    const prefix = icp.fields.i as string;
    const state = processor.identifiers.get(prefix);
    expect(state).toBeDefined();
    expect(state!.firstSeenOrdinal).toBe(99);
    expect(state!.firstSeenDatetime).toBe("2026-01-01T00:00:00Z");
  });

  // ---------------------------------------------------------------------------
  // C09: EO trait -> interaction rejected via IdentifierState
  // ---------------------------------------------------------------------------

  it("C09: EO trait -> interaction rejected", async () => {
    const { icp, siger, kp1 } = await buildSignedInceptionWithTraits({ eo: true });

    // Create IdentifierState from inception
    const state = IdentifierState.fromInception(icp.fields);

    expect(state.isEstablishmentOnly).toBe(true);

    // Build an interaction event
    const ixn = new InteractionBuilder(testHashFn)
      .identifier(icp.prefix)
      .previousEvent(icp.said)
      .sequenceNumber(1)
      .build();

    // Attempting to apply interaction should throw
    expect(() => {
      state.applyEvent(ixn.fields);
    }).toThrow(ValidationError);
    expect(() => {
      state.applyEvent(ixn.fields);
    }).toThrow(/EstablishmentOnly/);
  });

  // ---------------------------------------------------------------------------
  // C10: DND trait
  // ---------------------------------------------------------------------------

  it("C10: DND trait is recorded in state", async () => {
    const { icp } = await buildSignedInceptionWithTraits({ dnd: true });

    const state = IdentifierState.fromInception(icp.fields);

    expect(state.isDoNotDelegate).toBe(true);
    // DND is a flag — enforcement of "do not delegate" would be at the
    // delegation approval logic level, not in basic state transitions.
    // Verify the trait is correctly stored in the snapshot.
    const snap = state.snapshot();
    expect(snap.c).toContain("DND");
  });

  // ---------------------------------------------------------------------------
  // Config defaults
  // ---------------------------------------------------------------------------

  it("config defaults are as expected", () => {
    expect(DEFAULT_PROCESSOR_CONFIG.promiscuous).toBe(true);
    expect(DEFAULT_PROCESSOR_CONFIG.defaultLocal).toBe(false);
    expect(DEFAULT_PROCESSOR_CONFIG.replayMode).toBe(false);
    expect(DEFAULT_PROCESSOR_CONFIG.directMode).toBe(true);
    expect(DEFAULT_PROCESSOR_CONFIG.readOnly).toBe(false);
  });
});
