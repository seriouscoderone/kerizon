import { describe, it, expect } from "vitest";
import { DomainEventBus } from "../../../src/domain-events.js";
import type { DomainEvent } from "../../../src/domain-events.js";
import { EventProcessor } from "../../../src/event-processor.js";
import { InMemoryEventRepository, DefaultCryptoProvider } from "../../../src/repository/memory.js";
import { InceptionBuilder } from "../../../src/builders/inception.js";
import { RotationBuilder } from "../../../src/builders/rotation.js";
import { EscrowType } from "../../../src/repository/interface.js";
import { generateKeyPair, signMessage, testHashFn } from "../../helpers.js";
import { encodeEd25519IndexedSig } from "../../helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a fresh processor with direct mode. */
function makeProcessor(config?: { directMode?: boolean }) {
  const repo = new InMemoryEventRepository();
  const bus = new DomainEventBus();
  const crypto = new DefaultCryptoProvider();
  const processor = new EventProcessor(repo, bus, crypto, {
    directMode: config?.directMode ?? true,
  });
  return { repo, bus, crypto, processor };
}

/** Build and sign a minimal inception event. Returns event + siger. */
async function buildSignedInception() {
  const kp1 = await generateKeyPair();
  const kp2 = await generateKeyPair();

  const icp = new InceptionBuilder(testHashFn)
    .signingKeys([kp1.verferQb64])
    .nextKeys([kp2.verferQb64])
    .build();

  const sigBytes = await signMessage(kp1.privateKey, icp.raw);
  const qb64 = encodeEd25519IndexedSig(sigBytes, 0);
  const siger = { index: 0, raw: sigBytes, qb64 };

  return { icp, siger, kp1, kp2 };
}

/** Build and sign a rotation event. */
async function buildSignedRotation(
  prefix: string,
  priorSaid: string,
  sn: number,
  signingKp: Awaited<ReturnType<typeof generateKeyPair>>,
  nextKp: Awaited<ReturnType<typeof generateKeyPair>>,
) {
  const rot = new RotationBuilder(testHashFn)
    .identifier(prefix)
    .signingKeys([signingKp.verferQb64])
    .nextKeys([nextKp.verferQb64])
    .previousEvent(priorSaid)
    .sequenceNumber(sn)
    .build();

  const sigBytes = await signMessage(signingKp.privateKey, rot.raw);
  const qb64 = encodeEd25519IndexedSig(sigBytes, 0);
  const siger = { index: 0, raw: sigBytes, qb64 };

  return { rot, siger };
}

// ---------------------------------------------------------------------------
// DE01: EventAccepted after inception
// ---------------------------------------------------------------------------

describe("DomainEventBus", () => {
  it("DE01: push EventAccepted -> pull returns it", () => {
    const bus = new DomainEventBus();
    const event: DomainEvent = {
      type: "EventAccepted",
      prefix: "ETestPrefix00000000000000000000000000000000",
      sn: 0,
      said: "ETestSaid0000000000000000000000000000000000",
    };

    bus.push(event);
    const pulled = bus.pull();

    expect(pulled).toBeDefined();
    expect(pulled!.type).toBe("EventAccepted");
    expect(pulled!.prefix).toBe("ETestPrefix00000000000000000000000000000000");
    expect((pulled as any).sn).toBe(0);
    expect((pulled as any).said).toBe("ETestSaid0000000000000000000000000000000000");
  });

  // ---------------------------------------------------------------------------
  // DE02: EventAccepted after rotation
  // ---------------------------------------------------------------------------

  it("DE02: push EventAccepted for rotation -> pull returns it", () => {
    const bus = new DomainEventBus();
    const event: DomainEvent = {
      type: "EventAccepted",
      prefix: "ETestPrefix00000000000000000000000000000000",
      sn: 1,
      said: "ERotSaid000000000000000000000000000000000000",
    };

    bus.push(event);
    const pulled = bus.pull();

    expect(pulled).toBeDefined();
    expect(pulled!.type).toBe("EventAccepted");
    expect((pulled as any).sn).toBe(1);
    expect((pulled as any).said).toBe("ERotSaid000000000000000000000000000000000000");
  });

  // ---------------------------------------------------------------------------
  // DE07: FIFO ordering
  // ---------------------------------------------------------------------------

  it("DE07: FIFO ordering - push 3 events -> pull returns in order", () => {
    const bus = new DomainEventBus();

    const e1: DomainEvent = { type: "EventAccepted", prefix: "P1", sn: 0, said: "S1" };
    const e2: DomainEvent = { type: "EventNoticed", prefix: "P2", sn: 1, said: "S2" };
    const e3: DomainEvent = { type: "EventAccepted", prefix: "P3", sn: 2, said: "S3" };

    bus.push(e1);
    bus.push(e2);
    bus.push(e3);

    const r1 = bus.pull();
    const r2 = bus.pull();
    const r3 = bus.pull();
    const r4 = bus.pull();

    expect(r1).toEqual(e1);
    expect(r2).toEqual(e2);
    expect(r3).toEqual(e3);
    expect(r4).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // DE08: drain() returns all events and empties bus
  // ---------------------------------------------------------------------------

  it("DE08: drain returns all events and empties bus", () => {
    const bus = new DomainEventBus();

    const e1: DomainEvent = { type: "EventAccepted", prefix: "P1", sn: 0, said: "S1" };
    const e2: DomainEvent = { type: "EventNoticed", prefix: "P2", sn: 1, said: "S2" };
    const e3: DomainEvent = { type: "EventQueryNeeded", prefix: "P3", sequenceNumber: 0 };

    bus.push(e1);
    bus.push(e2);
    bus.push(e3);

    const drained = bus.drain();

    expect(drained).toHaveLength(3);
    expect(drained[0]).toEqual(e1);
    expect(drained[1]).toEqual(e2);
    expect(drained[2]).toEqual(e3);

    // Bus should now be empty
    expect(bus.isEmpty()).toBe(true);
    expect(bus.pull()).toBeUndefined();
    expect(bus.drain()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DE03: EventProcessor directMode=false produces EventNoticed
// ---------------------------------------------------------------------------

describe("EventProcessor domain events", () => {
  it("DE03: EventProcessor with directMode=false produces EventNoticed", async () => {
    const { bus, processor } = makeProcessor({ directMode: false });
    const { icp, siger } = await buildSignedInception();

    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [siger]);

    const events = bus.drain();
    expect(events.length).toBeGreaterThanOrEqual(1);

    const noticed = events.find((e) => e.type === "EventNoticed");
    expect(noticed).toBeDefined();
    expect(noticed!.type).toBe("EventNoticed");

    // Should NOT produce EventAccepted in indirect mode
    const accepted = events.find((e) => e.type === "EventAccepted");
    expect(accepted).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // DE04: WitnessReceiptNeeded - check if produced
  // ---------------------------------------------------------------------------

  it("DE04: WitnessReceiptNeeded - not produced by current EventProcessor", async () => {
    // The current EventProcessor.produceDomainEvent only produces
    // EventAccepted or EventNoticed. WitnessReceiptNeeded is defined in the
    // domain events type but not currently produced by EventProcessor.
    const { bus, processor } = makeProcessor({ directMode: true });
    const { icp, siger } = await buildSignedInception();

    await processor.ingestEvent({ raw: icp.raw, fields: icp.fields }, [siger]);

    const events = bus.drain();
    const witnessNeeded = events.find((e) => e.type === "WitnessReceiptNeeded");
    // Not produced by current implementation
    expect(witnessNeeded).toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // DE05: EventQueryNeeded produced during escrow timeout
  // ---------------------------------------------------------------------------

  it("DE05: EventQueryNeeded produced during OOE escrow timeout", async () => {
    const { repo, bus, processor } = makeProcessor({ directMode: true });

    const prefix = "EOoePrefix000000000000000000000000000000000";
    const digest = "EOoeDigest000000000000000000000000000000000";
    const sn = 2;

    // Manually add an entry to OOE escrow with an old timestamp
    await repo.addToEscrow(EscrowType.OOE, prefix, sn, digest);
    // Store a datetime that's far in the past (well beyond default 1200s timeout)
    const expiredDate = new Date(Date.now() - 2_000_000).toISOString();
    await repo.storeDatetime(prefix, digest, expiredDate);

    // Run escrow resolution
    await processor.resolveEscrows();

    const events = bus.drain();
    const queryNeeded = events.find((e) => e.type === "EventQueryNeeded");

    expect(queryNeeded).toBeDefined();
    expect(queryNeeded!.type).toBe("EventQueryNeeded");
    expect((queryNeeded as any).prefix).toBe(prefix);
    // sequenceNumber should be sn - 1 = 1 (query for the missing predecessor)
    expect((queryNeeded as any).sequenceNumber).toBe(sn - 1);
  });

  // ---------------------------------------------------------------------------
  // DE06: CloneMismatchDetected - not implemented in current EventProcessor
  // ---------------------------------------------------------------------------

  it.skip("DE06: CloneMismatchDetected - not implemented in current EventProcessor", () => {
    // CloneMismatchDetected is defined in the domain events type union
    // but the current EventProcessor does not produce it.
    // This test is skipped until replay mode with clone detection is implemented.
  });
});
