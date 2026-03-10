import { describe, it, expect, beforeEach } from "vitest";
import { EventProcessor } from "../../../src/event-processor.js";
import { DomainEventBus } from "../../../src/domain-events.js";
import { InMemoryEventRepository, DefaultCryptoProvider } from "../../../src/repository/memory.js";
import {
  UnverifiedReceiptError,
  UnverifiedWitnessReceiptError,
  UnverifiedTransferableReceiptError,
} from "../../../src/errors.js";
import {
  generateKeyPair,
  signMessage,
  testHashFn,
  encodeEd25519IndexedSig,
} from "../../helpers.js";
import { InceptionBuilder } from "../../../src/builders/inception.js";
import { ReceiptBuilder } from "../../../src/builders/receipt.js";
import type { IndexedSiger, CigarSig } from "../../../src/verification.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeSignedSiger(
  privateKey: CryptoKey,
  raw: Uint8Array,
  index: number,
): Promise<IndexedSiger> {
  const sigBytes = await signMessage(privateKey, raw);
  const qb64 = encodeEd25519IndexedSig(sigBytes, index);
  return { index, raw: sigBytes, qb64 };
}

// ---------------------------------------------------------------------------
// RC01-RC07: Receipt processing tests
// ---------------------------------------------------------------------------

describe("EventProcessor receipts", () => {
  let repo: InMemoryEventRepository;
  let bus: DomainEventBus;
  let crypto: DefaultCryptoProvider;
  let processor: EventProcessor;

  beforeEach(() => {
    repo = new InMemoryEventRepository();
    bus = new DomainEventBus();
    crypto = new DefaultCryptoProvider();
    processor = new EventProcessor(repo, bus, crypto);
  });

  /**
   * Helper: ingest an inception event and return the built event info.
   */
  async function ingestInception() {
    const kp = await generateKeyPair();
    const built = new InceptionBuilder(testHashFn)
      .signingKeys([kp.verferQb64])
      .nextKeys([kp.verferQb64])
      .build();

    const siger = await makeSignedSiger(kp.privateKey, built.raw, 0);
    await processor.ingestEvent(
      { raw: built.raw, fields: built.fields },
      [siger],
    );
    return { built, kp };
  }

  it("RC01: non-transferable receipt with valid cigar is stored", async () => {
    const { built, kp } = await ingestInception();

    // Build a receipt referencing the inception event
    const receipt = new ReceiptBuilder()
      .forEvent({ prefix: built.prefix, sn: 0, said: built.said })
      .build();

    // Create a cigar (non-transferable receipt signature)
    const receiptorKp = await generateKeyPair();
    const sigBytes = await signMessage(receiptorKp.privateKey, built.raw);

    const cigar: CigarSig = {
      verferQb64: receiptorKp.verferQb64,
      sigRaw: sigBytes,
    };

    await processor.ingestReceipt(
      { raw: receipt.raw, fields: receipt.fields },
      { nonTransferableSignatures: [cigar] },
    );

    // Check that the receipt was stored in the repository
    const receipts = await repo.retrieveNonTransferableReceipts(
      built.prefix,
      built.said,
    );
    expect(receipts.length).toBe(1);
    expect(receipts[0].receiptorPrefix).toBe(receiptorKp.verferQb64);
  });

  it("RC02: witness receipt is stored", async () => {
    const { built, kp } = await ingestInception();

    const receipt = new ReceiptBuilder()
      .forEvent({ prefix: built.prefix, sn: 0, said: built.said })
      .build();

    // Create a witness indexed signature
    const witnessKp = await generateKeyPair();
    const witSiger = await makeSignedSiger(witnessKp.privateKey, built.raw, 0);

    await processor.ingestReceipt(
      { raw: receipt.raw, fields: receipt.fields },
      { witnessSignatures: [witSiger] },
    );

    // Check witness signatures stored
    const witSigs = await repo.retrieveWitnessSignatures(
      built.prefix,
      built.said,
    );
    expect(witSigs.length).toBe(1);
    expect(witSigs[0].qb64).toBe(witSiger.qb64);
  });

  it("RC03: transferable receipt is stored", async () => {
    const { built, kp } = await ingestInception();

    const receipt = new ReceiptBuilder()
      .forEvent({ prefix: built.prefix, sn: 0, said: built.said })
      .build();

    // Create a transferable receipt group
    const receiptorKp = await generateKeyPair();
    const receiptorSiger = await makeSignedSiger(
      receiptorKp.privateKey,
      built.raw,
      0,
    );

    await processor.ingestReceipt(
      { raw: receipt.raw, fields: receipt.fields },
      {
        transferableSignatureGroups: [
          {
            prefix: receiptorKp.verferQb64,
            sn: 0,
            said: "EReceiptorSaid0000000000000000000000000000000",
            siger: receiptorSiger,
          },
        ],
      },
    );

    // Check transferable receipts stored
    const transReceipts = await repo.retrieveTransferableReceipts(
      built.prefix,
      built.said,
    );
    expect(transReceipts.length).toBe(1);
    expect(transReceipts[0].receiptorPrefix).toBe(receiptorKp.verferQb64);
  });

  it("RC04: non-transferable receipt before event throws UnverifiedReceiptError", async () => {
    const unknownPrefix = "ENoSuchPrefix000000000000000000000000000000";
    const unknownSaid = "ENoSuchSaid00000000000000000000000000000000";

    const receipt = new ReceiptBuilder()
      .forEvent({ prefix: unknownPrefix, sn: 0, said: unknownSaid })
      .build();

    const receiptorKp = await generateKeyPair();
    const sigBytes = await signMessage(receiptorKp.privateKey, receipt.raw);

    await expect(
      processor.ingestReceipt(
        { raw: receipt.raw, fields: receipt.fields },
        {
          nonTransferableSignatures: [
            { verferQb64: receiptorKp.verferQb64, sigRaw: sigBytes },
          ],
        },
      ),
    ).rejects.toThrow(UnverifiedReceiptError);
  });

  it("RC05: witness receipt before event throws UnverifiedWitnessReceiptError", async () => {
    const unknownPrefix = "ENoSuchPrefix000000000000000000000000000000";
    const unknownSaid = "ENoSuchSaid00000000000000000000000000000000";

    const receipt = new ReceiptBuilder()
      .forEvent({ prefix: unknownPrefix, sn: 0, said: unknownSaid })
      .build();

    const witnessKp = await generateKeyPair();
    const witSiger = await makeSignedSiger(
      witnessKp.privateKey,
      receipt.raw,
      0,
    );

    await expect(
      processor.ingestReceipt(
        { raw: receipt.raw, fields: receipt.fields },
        { witnessSignatures: [witSiger] },
      ),
    ).rejects.toThrow(UnverifiedWitnessReceiptError);
  });

  it("RC06: transferable receipt before event throws UnverifiedTransferableReceiptError", async () => {
    const unknownPrefix = "ENoSuchPrefix000000000000000000000000000000";
    const unknownSaid = "ENoSuchSaid00000000000000000000000000000000";

    const receipt = new ReceiptBuilder()
      .forEvent({ prefix: unknownPrefix, sn: 0, said: unknownSaid })
      .build();

    const receiptorKp = await generateKeyPair();
    const receiptorSiger = await makeSignedSiger(
      receiptorKp.privateKey,
      receipt.raw,
      0,
    );

    await expect(
      processor.ingestReceipt(
        { raw: receipt.raw, fields: receipt.fields },
        {
          transferableSignatureGroups: [
            {
              prefix: receiptorKp.verferQb64,
              sn: 0,
              said: "EReceiptorSaid0000000000000000000000000000000",
              siger: receiptorSiger,
            },
          ],
        },
      ),
    ).rejects.toThrow(UnverifiedTransferableReceiptError);
  });

  it("RC07: receipt for existing event stores normally", async () => {
    const { built, kp } = await ingestInception();

    const receipt = new ReceiptBuilder()
      .forEvent({ prefix: built.prefix, sn: 0, said: built.said })
      .build();

    // All three receipt types at once
    const receiptorKp = await generateKeyPair();
    const cigarSigBytes = await signMessage(receiptorKp.privateKey, built.raw);
    const witnessKp = await generateKeyPair();
    const witSiger = await makeSignedSiger(witnessKp.privateKey, built.raw, 0);
    const transKp = await generateKeyPair();
    const transSiger = await makeSignedSiger(transKp.privateKey, built.raw, 0);

    await processor.ingestReceipt(
      { raw: receipt.raw, fields: receipt.fields },
      {
        nonTransferableSignatures: [
          { verferQb64: receiptorKp.verferQb64, sigRaw: cigarSigBytes },
        ],
        witnessSignatures: [witSiger],
        transferableSignatureGroups: [
          {
            prefix: transKp.verferQb64,
            sn: 0,
            said: "ETransReceiptor000000000000000000000000000000",
            siger: transSiger,
          },
        ],
      },
    );

    // Verify all three types were stored
    const ntReceipts = await repo.retrieveNonTransferableReceipts(
      built.prefix,
      built.said,
    );
    expect(ntReceipts.length).toBe(1);

    const witSigs = await repo.retrieveWitnessSignatures(
      built.prefix,
      built.said,
    );
    // Witness sigs include both the inception sigs and the receipt wit sigs
    expect(witSigs.length).toBeGreaterThanOrEqual(1);

    const transReceipts = await repo.retrieveTransferableReceipts(
      built.prefix,
      built.said,
    );
    expect(transReceipts.length).toBe(1);
  });
});
