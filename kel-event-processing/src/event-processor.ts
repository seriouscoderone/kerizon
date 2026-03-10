import type { ProcessorConfig, EscrowTimeouts } from "./config.js";
import { DEFAULT_PROCESSOR_CONFIG, DEFAULT_ESCROW_TIMEOUTS } from "./config.js";
import type { DomainEvent } from "./domain-events.js";
import { DomainEventBus } from "./domain-events.js";
import type { EventRepository } from "./repository/interface.js";
import type { IndexedSiger, CryptoProvider } from "./verification.js";
import { verifySigs, satisfyThreshold, verifyWitnessSigs } from "./verification.js";
import type { CigarSig } from "./verification.js";
import { IdentifierState } from "./identifier-state.js";
import {
  Ilk,
  INCEPTION_ILKS,
  ROTATION_ILKS,
} from "./types.js";
import {
  ValidationError,
  OutOfOrderError,
  InsufficientSignaturesError,
  InsufficientWitnessesError,
  MissingDelegationError,
  PendingDelegationApprovalError,
  ProvenanceMismatchError,
  UnverifiedWitnessReceiptError,
  UnverifiedReceiptError,
  UnverifiedTransferableReceiptError,
  DuplicitousEventError,
} from "./errors.js";
import { EscrowType } from "./repository/interface.js";
import { EscrowReason } from "./views/pending-event.js";

/** Map from EscrowReason to EscrowType for storage. */
const REASON_TO_TYPE: Record<string, EscrowType> = {
  [EscrowReason.OUT_OF_ORDER]: EscrowType.OOE,
  [EscrowReason.PARTIAL_SIGNATURES]: EscrowType.PSE,
  [EscrowReason.PARTIAL_WITNESSES]: EscrowType.PWE,
  [EscrowReason.PENDING_DELEGATION]: EscrowType.PDE,
  [EscrowReason.DELEGABLE]: EscrowType.DELEGABLE,
  [EscrowReason.MISFIT_SOURCE]: EscrowType.MFE,
  [EscrowReason.UNVERIFIED_WITNESS_RECEIPT]: EscrowType.UWE,
  [EscrowReason.UNVERIFIED_RECEIPT]: EscrowType.URE,
  [EscrowReason.UNVERIFIED_TRANSFERABLE_RECEIPT]: EscrowType.VRE,
  [EscrowReason.LIKELY_DUPLICITOUS]: EscrowType.LDE,
};

/** Escrow processing order per spec Section 11.2. */
const ESCROW_PROCESSING_ORDER: EscrowType[] = [
  EscrowType.OOE,
  EscrowType.UWE,
  EscrowType.URE,
  EscrowType.VRE,
  EscrowType.PDE,
  EscrowType.PWE,
  EscrowType.PSE,
  EscrowType.LDE,
];

/** Map from EscrowType to timeout config field name. */
function getTimeoutSeconds(escrowType: EscrowType, timeouts: EscrowTimeouts): number {
  switch (escrowType) {
    case EscrowType.OOE: return timeouts.outOfOrder;
    case EscrowType.PSE: return timeouts.partialSignatures;
    case EscrowType.PWE: return timeouts.partialWitnesses;
    case EscrowType.PDE: return timeouts.partialDelegation;
    case EscrowType.DELEGABLE: return timeouts.delegable;
    case EscrowType.MFE: return timeouts.misfitSource;
    case EscrowType.UWE: return timeouts.unverifiedWitnessReceipt;
    case EscrowType.URE: return timeouts.unverifiedReceipt;
    case EscrowType.VRE: return timeouts.unverifiedTransferableReceipt;
    case EscrowType.LDE: return timeouts.likelyDuplicitous;
  }
}

/**
 * EventProcessor — Domain service coordinating event dispatch and escrow management.
 */
export class EventProcessor {
  /** Lazy-loading cache of IdentifierState instances. */
  readonly identifiers = new Map<string, IdentifierState>();
  /** Set of locally-controlled AID prefixes. */
  readonly localPrefixes = new Set<string>();

  private readonly repository: EventRepository;
  private readonly bus: DomainEventBus;
  private readonly config: ProcessorConfig;
  private readonly timeouts: EscrowTimeouts;
  private readonly crypto: CryptoProvider;

  constructor(
    repository: EventRepository,
    bus: DomainEventBus,
    crypto: CryptoProvider,
    config?: Partial<ProcessorConfig>,
    timeouts?: Partial<EscrowTimeouts>,
  ) {
    this.repository = repository;
    this.bus = bus;
    this.crypto = crypto;
    this.config = { ...DEFAULT_PROCESSOR_CONFIG, ...config };
    this.timeouts = { ...DEFAULT_ESCROW_TIMEOUTS, ...timeouts };
  }

  /**
   * Main entry point for processing a key event.
   */
  async ingestEvent(
    event: { raw: Uint8Array; fields: Record<string, unknown> },
    signatures: IndexedSiger[],
    options: {
      witnessSignatures?: IndexedSiger[];
      delegatorSeqNum?: number;
      delegatorDigest?: string;
      firstSeenOrdinal?: number;
      firstSeenDatetime?: string;
      local?: boolean;
    } = {},
  ): Promise<void> {
    const { raw, fields } = event;
    const prefix = fields.i as string;
    const ilk = fields.t as string;
    const sn = parseInt(fields.s as string, 16);
    const said = fields.d as string;
    const local = options.local ?? this.config.defaultLocal;

    try {
      // Inception handling
      if (INCEPTION_ILKS.has(ilk as Ilk)) {
        await this.processInception(raw, fields, signatures, prefix, sn, said, local, options);
        return;
      }

      // Non-inception: need existing identifier
      const state = this.identifiers.get(prefix);
      if (!state) {
        throw new OutOfOrderError(
          `No inception found for "${prefix}", cannot process ${ilk}`,
          prefix,
          sn,
        );
      }

      const expectedSn = state.sequenceNumber + 1;

      if (sn > expectedSn) {
        throw new OutOfOrderError(
          `Out of order: expected sn <= ${expectedSn}, got ${sn}`,
          prefix,
          sn,
        );
      }

      if (sn === expectedSn) {
        // Normal next event
        state.applyEvent(fields);
        await state.commitEvent(raw, fields, signatures, options.witnessSignatures ?? [], this.repository, {
          local,
          readOnly: this.config.readOnly,
          firstSeenOrdinal: options.firstSeenOrdinal,
          firstSeenDatetime: options.firstSeenDatetime,
          delegatorSeqNum: options.delegatorSeqNum,
          delegatorDigest: options.delegatorDigest,
        });
        this.produceDomainEvent(prefix, sn, said);
        return;
      }

      // sn <= state.sn — check for recovery or duplicity
      if (ROTATION_ILKS.has(ilk as Ilk)) {
        // Check if valid recovery rotation
        const lastEstSn = state.lastEstablishment.sn;
        let isRecovery = false;
        if (ilk === Ilk.Rotation && lastEstSn < sn && sn <= state.sequenceNumber) {
          isRecovery = true;
        } else if (ilk === Ilk.DelegatedRotation && lastEstSn <= sn && sn <= state.sequenceNumber) {
          isRecovery = true;
        }

        if (isRecovery) {
          state.applyEvent(fields);
          await state.commitEvent(raw, fields, signatures, options.witnessSignatures ?? [], this.repository, {
            local,
            readOnly: this.config.readOnly,
            delegatorSeqNum: options.delegatorSeqNum,
            delegatorDigest: options.delegatorDigest,
          });
          this.produceDomainEvent(prefix, sn, said);
          return;
        }
      }

      // Check for duplicate (same SAID) or duplicitous (different SAID)
      const existingDigest = await this.repository.getLastEventDigest(prefix, sn);
      if (existingDigest === said) {
        // Same event — accumulate signatures (idempotent)
        if (signatures.length > 0) {
          await this.repository.storeControllerSignatures(prefix, said, signatures);
        }
        return;
      }

      throw new DuplicitousEventError(
        `Duplicitous event at sn ${sn} for "${prefix}"`,
        prefix,
        sn,
      );
    } catch (error) {
      await this.routeToEscrow(error, raw, fields, signatures, prefix, sn, said, options);
    }
  }

  /**
   * Process a receipt message.
   */
  async ingestReceipt(
    receipt: { raw: Uint8Array; fields: Record<string, unknown> },
    options: {
      nonTransferableSignatures?: CigarSig[];
      witnessSignatures?: IndexedSiger[];
      transferableSignatureGroups?: Array<{
        prefix: string;
        sn: number;
        said: string;
        siger: IndexedSiger;
      }>;
      local?: boolean;
    } = {},
  ): Promise<void> {
    const { fields } = receipt;
    const prefix = fields.i as string;
    const sn = parseInt(fields.s as string, 16);
    const said = fields.d as string;

    // Look up the receipted event
    const eventBytes = await this.repository.retrieveEvent(prefix, said);
    if (!eventBytes) {
      // Event not found — escrow receipts
      if (options.nonTransferableSignatures?.length) {
        throw new UnverifiedReceiptError(
          `Receipted event not found for ${prefix} sn=${sn}`,
        );
      }
      if (options.witnessSignatures?.length) {
        throw new UnverifiedWitnessReceiptError(
          `Receipted event not found for ${prefix} sn=${sn}`,
        );
      }
      if (options.transferableSignatureGroups?.length) {
        throw new UnverifiedTransferableReceiptError(
          `Receipted event not found for ${prefix} sn=${sn}`,
        );
      }
      return;
    }

    // Store non-transferable receipts
    if (options.nonTransferableSignatures?.length) {
      await this.repository.storeNonTransferableReceipts(
        prefix,
        said,
        options.nonTransferableSignatures.map((c) => ({
          receiptorPrefix: c.verferQb64,
          sigRaw: c.sigRaw,
          sigQb64: c.verferQb64,
        })),
      );
    }

    // Store witness signatures
    if (options.witnessSignatures?.length) {
      await this.repository.storeWitnessSignatures(prefix, said, options.witnessSignatures);
    }

    // Store transferable receipts
    if (options.transferableSignatureGroups?.length) {
      await this.repository.storeTransferableReceipts(
        prefix,
        said,
        options.transferableSignatureGroups.map((g) => ({
          receiptorPrefix: g.prefix,
          receiptorSn: g.sn,
          receiptorSaid: g.said,
          siger: g.siger,
        })),
      );
    }
  }

  /**
   * Periodic sweep of all escrow types.
   */
  async resolveEscrows(): Promise<void> {
    const now = Date.now();

    for (const escrowType of ESCROW_PROCESSING_ORDER) {
      const timeoutSec = getTimeoutSeconds(escrowType, this.timeouts);
      const timeoutMs = timeoutSec * 1000;
      const toRemove: Array<{ prefix: string; sn: number; digest: string }> = [];

      for await (const entry of this.repository.iterateEscrow(escrowType)) {
        const datetime = await this.repository.retrieveDatetime(entry.prefix, entry.digest);
        const escrowedAt = datetime ? new Date(datetime).getTime() : now;

        // Check timeout
        if (now - escrowedAt > timeoutMs) {
          toRemove.push(entry);
          if (escrowType === EscrowType.OOE) {
            this.bus.push({
              type: "EventQueryNeeded",
              prefix: entry.prefix,
              sequenceNumber: entry.sn > 0 ? entry.sn - 1 : 0,
            });
          }
          continue;
        }

        // LDE: evidence only, not re-processed
        if (escrowType === EscrowType.LDE) continue;

        // Try to re-process
        const eventBytes = await this.repository.retrieveEvent(entry.prefix, entry.digest);
        if (!eventBytes) continue;

        try {
          const eventFields = JSON.parse(new TextDecoder().decode(eventBytes));
          const sigs = await this.repository.retrieveControllerSignatures(entry.prefix, entry.digest);

          // Re-ingest
          await this.ingestEvent(
            { raw: eventBytes, fields: eventFields },
            sigs,
          );

          // If we get here without error, it was accepted
          toRemove.push(entry);
        } catch {
          // Still blocked — leave in escrow
        }
      }

      // Remove resolved/timed-out entries
      for (const entry of toRemove) {
        await this.repository.removeFromEscrow(escrowType, entry.prefix, entry.sn, entry.digest);
      }
    }
  }

  private async processInception(
    raw: Uint8Array,
    fields: Record<string, unknown>,
    signatures: IndexedSiger[],
    prefix: string,
    sn: number,
    said: string,
    local: boolean,
    options: {
      witnessSignatures?: IndexedSiger[];
      delegatorSeqNum?: number;
      delegatorDigest?: string;
      firstSeenOrdinal?: number;
      firstSeenDatetime?: string;
    },
  ): Promise<void> {
    if (this.identifiers.has(prefix)) {
      const existing = this.identifiers.get(prefix)!;
      if (existing.sequenceNumber === 0 && existing.latestEventSaid === said) {
        // Same inception — accumulate signatures
        if (signatures.length > 0) {
          await this.repository.storeControllerSignatures(prefix, said, signatures);
        }
        return;
      }
      throw new DuplicitousEventError(
        `Duplicitous inception for "${prefix}"`,
        prefix,
        0,
      );
    }

    const state = IdentifierState.fromInception(fields);
    this.identifiers.set(prefix, state);

    await state.commitEvent(raw, fields, signatures, options.witnessSignatures ?? [], this.repository, {
      local,
      readOnly: this.config.readOnly,
      firstSeenOrdinal: options.firstSeenOrdinal,
      firstSeenDatetime: options.firstSeenDatetime,
      delegatorSeqNum: options.delegatorSeqNum,
      delegatorDigest: options.delegatorDigest,
    });

    this.produceDomainEvent(prefix, 0, said);
  }

  private produceDomainEvent(prefix: string, sn: number, said: string): void {
    if (this.config.directMode) {
      this.bus.push({ type: "EventAccepted", prefix, sn, said });
    } else {
      this.bus.push({ type: "EventNoticed", prefix, sn, said });
    }
  }

  private async routeToEscrow(
    error: unknown,
    raw: Uint8Array,
    fields: Record<string, unknown>,
    signatures: IndexedSiger[],
    prefix: string,
    sn: number,
    said: string,
    options: {
      witnessSignatures?: IndexedSiger[];
      delegatorSeqNum?: number;
      delegatorDigest?: string;
    },
  ): Promise<void> {
    let escrowType: EscrowType | undefined;

    if (error instanceof OutOfOrderError) {
      escrowType = EscrowType.OOE;
    } else if (error instanceof InsufficientSignaturesError) {
      escrowType = EscrowType.PSE;
    } else if (error instanceof InsufficientWitnessesError) {
      escrowType = EscrowType.PWE;
    } else if (error instanceof MissingDelegationError) {
      escrowType = EscrowType.PDE;
    } else if (error instanceof PendingDelegationApprovalError) {
      escrowType = EscrowType.DELEGABLE;
    } else if (error instanceof ProvenanceMismatchError) {
      escrowType = EscrowType.MFE;
    } else if (error instanceof UnverifiedWitnessReceiptError) {
      escrowType = EscrowType.UWE;
    } else if (error instanceof UnverifiedReceiptError) {
      escrowType = EscrowType.URE;
    } else if (error instanceof UnverifiedTransferableReceiptError) {
      escrowType = EscrowType.VRE;
    } else if (error instanceof DuplicitousEventError) {
      escrowType = EscrowType.LDE;
    }

    if (escrowType) {
      // Store event and signatures in shared tables
      await this.repository.storeEvent(prefix, said, raw);
      if (signatures.length > 0) {
        await this.repository.storeControllerSignatures(prefix, said, signatures);
      }
      if (options.witnessSignatures?.length) {
        await this.repository.storeWitnessSignatures(prefix, said, options.witnessSignatures);
      }
      await this.repository.storeDatetime(prefix, said, new Date().toISOString());
      // Add to escrow index
      await this.repository.addToEscrow(escrowType, prefix, sn, said);
      return;
    }

    // Not an escrow-routable error — re-throw
    throw error;
  }
}
