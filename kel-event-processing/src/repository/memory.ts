import type { IndexedSiger, CryptoProvider } from "../verification.js";
import type { KeyStateSnapshot, EventProvenance } from "../types.js";
import type {
  EventRepository,
  NonTransferableReceipt,
  TransferableReceipt,
} from "./interface.js";
import { EscrowType } from "./interface.js";
import { digestKey, sequenceKey } from "./keys.js";

// ── Escrow entry shape ──────────────────────────────────────────────

interface EscrowEntry {
  prefix: string;
  sn: number;
  digest: string;
}

// ── InMemoryEventRepository ─────────────────────────────────────────

/** In-memory reference implementation of EventRepository. */
export class InMemoryEventRepository implements EventRepository {
  private events = new Map<string, Uint8Array>();
  private eventLog = new Map<string, string[]>();
  private firstSeenLog = new Map<string, string[]>();
  private firstSeenOrdinals = new Map<string, number>();
  private fnCounters = new Map<string, number>();
  private controllerSigs = new Map<string, IndexedSiger[]>();
  private witnessSigs = new Map<string, IndexedSiger[]>();
  private nonTransReceipts = new Map<string, NonTransferableReceipt[]>();
  private transReceipts = new Map<string, TransferableReceipt[]>();
  private datetimes = new Map<string, string>();
  private provenances = new Map<string, EventProvenance>();
  private delegationSeals = new Map<
    string,
    { seqNum: number; digest: string }
  >();
  private witnessStates = new Map<string, string[]>();
  private keyStates = new Map<string, KeyStateSnapshot>();
  private escrows = new Map<string, EscrowEntry[]>();

  // ── Event storage ─────────────────────────────────────────────────

  async storeEvent(
    prefix: string,
    digest: string,
    event: Uint8Array,
  ): Promise<void> {
    this.events.set(digestKey(prefix, digest), event);
  }

  async retrieveEvent(
    prefix: string,
    digest: string,
  ): Promise<Uint8Array | undefined> {
    return this.events.get(digestKey(prefix, digest));
  }

  // ── Log indexes ───────────────────────────────────────────────────

  async appendToEventLog(
    prefix: string,
    sequenceNumber: number,
    digest: string,
  ): Promise<void> {
    const k = sequenceKey(prefix, sequenceNumber);
    const existing = this.eventLog.get(k) ?? [];
    if (!existing.includes(digest)) {
      existing.push(digest);
    }
    this.eventLog.set(k, existing);
  }

  async getLastEventDigest(
    prefix: string,
    sequenceNumber: number,
  ): Promise<string | undefined> {
    const entries = this.eventLog.get(sequenceKey(prefix, sequenceNumber));
    if (!entries || entries.length === 0) return undefined;
    return entries[entries.length - 1];
  }

  async *iterateEventLogBackward(
    prefix: string,
  ): AsyncIterable<{ sn: number; digest: string }> {
    // Collect all sequence numbers for this prefix
    const snDigests: Array<{ sn: number; digest: string }> = [];
    for (const [key, digests] of this.eventLog) {
      if (key.startsWith(prefix + ":")) {
        const sn = parseInt(key.slice(prefix.length + 1), 10);
        if (!isNaN(sn) && digests.length > 0) {
          snDigests.push({ sn, digest: digests[digests.length - 1] });
        }
      }
    }
    snDigests.sort((a, b) => b.sn - a.sn);
    for (const entry of snDigests) {
      yield entry;
    }
  }

  async appendToFirstSeenLog(
    prefix: string,
    digest: string,
  ): Promise<number> {
    const counter = this.fnCounters.get(prefix) ?? 0;
    const fn = counter;
    this.fnCounters.set(prefix, counter + 1);
    const list = this.firstSeenLog.get(prefix) ?? [];
    list.push(digest);
    this.firstSeenLog.set(prefix, list);
    return fn;
  }

  async storeFirstSeenOrdinal(
    prefix: string,
    digest: string,
    ordinal: number,
  ): Promise<void> {
    this.firstSeenOrdinals.set(digestKey(prefix, digest), ordinal);
  }

  async getFirstSeenOrdinal(
    prefix: string,
    digest: string,
  ): Promise<number | undefined> {
    return this.firstSeenOrdinals.get(digestKey(prefix, digest));
  }

  // ── Signatures ────────────────────────────────────────────────────

  async storeControllerSignatures(
    prefix: string,
    digest: string,
    signatures: IndexedSiger[],
  ): Promise<void> {
    const k = digestKey(prefix, digest);
    const existing = this.controllerSigs.get(k) ?? [];
    for (const sig of signatures) {
      if (!existing.some((s) => s.qb64 === sig.qb64)) {
        existing.push(sig);
      }
    }
    this.controllerSigs.set(k, existing);
  }

  async retrieveControllerSignatures(
    prefix: string,
    digest: string,
  ): Promise<IndexedSiger[]> {
    return this.controllerSigs.get(digestKey(prefix, digest)) ?? [];
  }

  async storeWitnessSignatures(
    prefix: string,
    digest: string,
    signatures: IndexedSiger[],
  ): Promise<void> {
    const k = digestKey(prefix, digest);
    const existing = this.witnessSigs.get(k) ?? [];
    for (const sig of signatures) {
      if (!existing.some((s) => s.qb64 === sig.qb64)) {
        existing.push(sig);
      }
    }
    this.witnessSigs.set(k, existing);
  }

  async retrieveWitnessSignatures(
    prefix: string,
    digest: string,
  ): Promise<IndexedSiger[]> {
    return this.witnessSigs.get(digestKey(prefix, digest)) ?? [];
  }

  async storeNonTransferableReceipts(
    prefix: string,
    digest: string,
    couples: NonTransferableReceipt[],
  ): Promise<void> {
    const k = digestKey(prefix, digest);
    const existing = this.nonTransReceipts.get(k) ?? [];
    for (const couple of couples) {
      if (
        !existing.some(
          (r) =>
            r.receiptorPrefix === couple.receiptorPrefix &&
            r.sigQb64 === couple.sigQb64,
        )
      ) {
        existing.push(couple);
      }
    }
    this.nonTransReceipts.set(k, existing);
  }

  async retrieveNonTransferableReceipts(
    prefix: string,
    digest: string,
  ): Promise<NonTransferableReceipt[]> {
    return this.nonTransReceipts.get(digestKey(prefix, digest)) ?? [];
  }

  async storeTransferableReceipts(
    prefix: string,
    digest: string,
    quadruples: TransferableReceipt[],
  ): Promise<void> {
    const k = digestKey(prefix, digest);
    const existing = this.transReceipts.get(k) ?? [];
    for (const quad of quadruples) {
      if (
        !existing.some(
          (r) =>
            r.receiptorPrefix === quad.receiptorPrefix &&
            r.siger.qb64 === quad.siger.qb64,
        )
      ) {
        existing.push(quad);
      }
    }
    this.transReceipts.set(k, existing);
  }

  async retrieveTransferableReceipts(
    prefix: string,
    digest: string,
  ): Promise<TransferableReceipt[]> {
    return this.transReceipts.get(digestKey(prefix, digest)) ?? [];
  }

  // ── Metadata ──────────────────────────────────────────────────────

  async storeDatetime(
    prefix: string,
    digest: string,
    datetime: string,
  ): Promise<void> {
    const k = digestKey(prefix, digest);
    if (!this.datetimes.has(k)) {
      this.datetimes.set(k, datetime);
    }
  }

  async retrieveDatetime(
    prefix: string,
    digest: string,
  ): Promise<string | undefined> {
    return this.datetimes.get(digestKey(prefix, digest));
  }

  async storeProvenance(
    prefix: string,
    digest: string,
    provenance: EventProvenance,
  ): Promise<void> {
    this.provenances.set(digestKey(prefix, digest), provenance);
  }

  async retrieveProvenance(
    prefix: string,
    digest: string,
  ): Promise<EventProvenance | undefined> {
    return this.provenances.get(digestKey(prefix, digest));
  }

  async storeDelegationSeal(
    prefix: string,
    digest: string,
    seqNum: number,
    delegatorDigest: string,
  ): Promise<void> {
    this.delegationSeals.set(digestKey(prefix, digest), {
      seqNum,
      digest: delegatorDigest,
    });
  }

  async retrieveDelegationSeal(
    prefix: string,
    digest: string,
  ): Promise<{ seqNum: number; digest: string } | undefined> {
    return this.delegationSeals.get(digestKey(prefix, digest));
  }

  async removeDelegationSeal(
    prefix: string,
    digest: string,
  ): Promise<void> {
    this.delegationSeals.delete(digestKey(prefix, digest));
  }

  async storeWitnessState(
    prefix: string,
    digest: string,
    witnesses: string[],
  ): Promise<void> {
    this.witnessStates.set(digestKey(prefix, digest), witnesses);
  }

  async retrieveWitnessState(
    prefix: string,
    digest: string,
  ): Promise<string[] | undefined> {
    return this.witnessStates.get(digestKey(prefix, digest));
  }

  async storeKeyStateSnapshot(
    prefix: string,
    snapshot: KeyStateSnapshot,
  ): Promise<void> {
    this.keyStates.set(prefix, snapshot);
  }

  async retrieveKeyStateSnapshot(
    prefix: string,
  ): Promise<KeyStateSnapshot | undefined> {
    return this.keyStates.get(prefix);
  }

  // ── Parameterized escrow ops ──────────────────────────────────────

  async addToEscrow(
    escrowType: EscrowType,
    prefix: string,
    sequenceNumber: number,
    digest: string,
  ): Promise<void> {
    const entries = this.escrows.get(escrowType) ?? [];
    if (
      !entries.some(
        (e) =>
          e.prefix === prefix &&
          e.sn === sequenceNumber &&
          e.digest === digest,
      )
    ) {
      entries.push({ prefix, sn: sequenceNumber, digest });
    }
    this.escrows.set(escrowType, entries);
  }

  async *iterateEscrow(
    escrowType: EscrowType,
  ): AsyncIterable<{ prefix: string; sn: number; digest: string }> {
    const entries = this.escrows.get(escrowType) ?? [];
    for (const entry of [...entries]) {
      yield entry;
    }
  }

  async removeFromEscrow(
    escrowType: EscrowType,
    prefix: string,
    sequenceNumber: number,
    digest: string,
  ): Promise<void> {
    const entries = this.escrows.get(escrowType) ?? [];
    this.escrows.set(
      escrowType,
      entries.filter(
        (e) =>
          !(
            e.prefix === prefix &&
            e.sn === sequenceNumber &&
            e.digest === digest
          ),
      ),
    );
  }

  // ── Query ─────────────────────────────────────────────────────────

  async findSealingEvent(
    prefix: string,
    sealDigest: string,
  ): Promise<Uint8Array | undefined> {
    return this.events.get(digestKey(prefix, sealDigest));
  }
}

// ── DefaultCryptoProvider ───────────────────────────────────────────

/**
 * Default crypto provider using Web Crypto API.
 * Supports Ed25519 signature verification and SHA-256 digests.
 */
export class DefaultCryptoProvider implements CryptoProvider {
  async verifySignature(
    publicKeyBytes: Uint8Array,
    signatureBytes: Uint8Array,
    message: Uint8Array,
  ): Promise<boolean> {
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes.slice(),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        "Ed25519",
        key,
        signatureBytes.slice(),
        message.slice(),
      );
    } catch {
      return false;
    }
  }

  async digest(data: Uint8Array, _algorithm?: string): Promise<Uint8Array> {
    const hash = await crypto.subtle.digest("SHA-256", data.slice());
    return new Uint8Array(hash);
  }
}
