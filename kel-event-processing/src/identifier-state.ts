import type { HashFn } from "cesr-ts";
import type {
  Threshold,
  KeyStateSnapshot,
  EstablishmentDetail,
  EstablishmentLocator,
  EventProvenance,
} from "./types.js";
import {
  Ilk,
  ESTABLISHMENT_ILKS,
  INCEPTION_ILKS,
  ROTATION_ILKS,
  parseTraits,
} from "./types.js";
import {
  ValidationError,
  OutOfOrderError,
  InsufficientSignaturesError,
  InsufficientWitnessesError,
  MissingDelegationError,
  DuplicitousEventError,
} from "./errors.js";
import type { EventRepository } from "./repository/interface.js";
import type { IndexedSiger, CryptoProvider } from "./verification.js";
import {
  verifySigs,
  satisfyThreshold,
  thresholdSize,
  verifyPreRotation,
  verifyWitnessSigs,
} from "./verification.js";

/**
 * Derive the new witness list after a rotation event.
 */
function deriveBacks(
  currentWitnesses: string[],
  br: string[],
  ba: string[],
): string[] {
  if (new Set(br).size !== br.length) {
    throw new ValidationError("Duplicate entries in witness removes (br)");
  }
  if (new Set(ba).size !== ba.length) {
    throw new ValidationError("Duplicate entries in witness adds (ba)");
  }
  const currentSet = new Set(currentWitnesses);
  for (const w of br) {
    if (!currentSet.has(w)) {
      throw new ValidationError(
        `Witness remove "${w}" not found in current witness list`,
      );
    }
  }
  const brSet = new Set(br);
  for (const w of ba) {
    if (brSet.has(w)) {
      throw new ValidationError(
        `Witness "${w}" appears in both removes (br) and adds (ba)`,
      );
    }
  }
  for (const w of ba) {
    if (currentSet.has(w)) {
      throw new ValidationError(
        `Witness add "${w}" already exists in current witness list`,
      );
    }
  }
  const newWitnesses = currentWitnesses.filter((w) => !brSet.has(w)).concat(ba);
  if (new Set(newWitnesses).size !== newWitnesses.length) {
    throw new ValidationError("Derived witness list contains duplicates");
  }
  return newWitnesses;
}

/**
 * Check if a rotation event is a valid recovery attempt.
 */
function isValidSupersede(
  ilk: string,
  sn: number,
  keverSn: number,
  lastEstSn: number,
): boolean {
  if (ilk === Ilk.Interaction) return false;
  if (ilk === Ilk.Rotation) {
    return lastEstSn < sn && sn <= keverSn;
  }
  if (ilk === Ilk.DelegatedRotation) {
    return lastEstSn <= sn && sn <= keverSn;
  }
  return false;
}

/**
 * IdentifierState — Aggregate root for a single AID.
 *
 * Encapsulates the complete key state of a single identifier
 * and enforces all invariants on state transitions.
 */
export class IdentifierState {
  /** AID prefix. */
  prefix: string = "";
  /** Whether the identifier is transferable (has next-key digests). */
  transferable: boolean = false;

  /** Sequence number of latest event. */
  sequenceNumber: number = 0;
  /** First-seen ordinal of latest event. */
  firstSeenOrdinal: number = 0;
  /** First-seen datetime. */
  firstSeenDatetime: string = "";
  /** SAID of latest event. */
  latestEventSaid: string = "";
  /** Ilk of latest event. */
  eventIlk: string = "";

  /** Current signing keys (qb64). */
  signingKeys: string[] = [];
  /** Current signing threshold. */
  signingThreshold: Threshold = "0";

  /** Next key digests (qb64). */
  nextKeyDigests: string[] = [];
  /** Next rotation threshold. */
  nextThreshold: Threshold = "0";

  /** Current witness AID prefixes. */
  witnesses: string[] = [];
  /** Witness threshold (TOAD). */
  witnessThreshold: number = 0;
  /** Witnesses removed in latest est event. */
  witnessCuts: string[] = [];
  /** Witnesses added in latest est event. */
  witnessAdds: string[] = [];

  /** Whether this is a delegated identifier. */
  isDelegated: boolean = false;
  /** Delegator prefix (empty if not delegated). */
  delegatorPrefix: string = "";

  /** EO trait active. */
  isEstablishmentOnly: boolean = false;
  /** DND trait active. */
  isDoNotDelegate: boolean = false;

  /** Configuration traits. */
  private configTraits: string[] = [];

  /** Sequence number and SAID of last establishment event. */
  lastEstablishment: EstablishmentLocator = { sn: 0, digest: "" };

  /** Prior event SAID (for chain linking). */
  private priorSaid: string = "";

  private constructor() {}

  /**
   * Create a new IdentifierState from a validated inception event.
   */
  static fromInception(fields: Record<string, unknown>): IdentifierState {
    const state = new IdentifierState();
    state.validateAndApplyInception(fields);
    return state;
  }

  /**
   * Restore an IdentifierState from a previously persisted KeyStateSnapshot.
   */
  static fromSnapshot(snapshot: KeyStateSnapshot): IdentifierState {
    const state = new IdentifierState();
    state.prefix = snapshot.i;
    state.sequenceNumber = parseInt(snapshot.s, 16);
    state.latestEventSaid = snapshot.d;
    state.eventIlk = snapshot.et;
    state.firstSeenOrdinal = parseInt(snapshot.f, 16);
    state.firstSeenDatetime = snapshot.dt;
    state.signingKeys = snapshot.k;
    state.signingThreshold = snapshot.kt;
    state.nextKeyDigests = snapshot.n;
    state.nextThreshold = snapshot.nt;
    state.witnesses = snapshot.b;
    state.witnessThreshold = parseInt(snapshot.bt, 16);
    state.witnessCuts = snapshot.ee.br;
    state.witnessAdds = snapshot.ee.ba;
    state.isDelegated = !!snapshot.di;
    state.delegatorPrefix = snapshot.di;
    state.transferable = snapshot.n.length > 0;
    state.priorSaid = snapshot.p;
    state.configTraits = snapshot.c;

    const traits = parseTraits(snapshot.c);
    state.isEstablishmentOnly = traits.estOnly;
    state.isDoNotDelegate = traits.doNotDelegate;
    state.lastEstablishment = {
      sn: parseInt(snapshot.ee.s, 16),
      digest: snapshot.ee.d,
    };

    return state;
  }

  /**
   * Validate and apply an inception event.
   */
  private validateAndApplyInception(fields: Record<string, unknown>): void {
    const ilk = fields.t as string;
    if (!INCEPTION_ILKS.has(ilk as Ilk)) {
      throw new ValidationError(`Expected inception ilk, got "${ilk}"`);
    }

    const sn = parseInt(fields.s as string, 16);
    if (sn !== 0) {
      throw new ValidationError("Inception event must have sn = 0");
    }

    const keys = fields.k as string[];
    const kt = fields.kt as Threshold;
    const nextDigests = fields.n as string[];
    const nt = fields.nt as Threshold;
    const witnessList = fields.b as string[];
    const bt = parseInt(fields.bt as string, 16);
    const configTraitsList = fields.c as string[];
    const anchors = fields.a as unknown[];
    const prefix = fields.i as string;
    const said = fields.d as string;

    // Validate signing keys
    if (!keys || keys.length === 0) {
      throw new ValidationError("At least one signing key is required");
    }

    // Validate threshold bounds
    const ktSize = typeof kt === "string" ? parseInt(kt, 10) : thresholdSize(kt);
    if (ktSize < 1 || ktSize > keys.length) {
      throw new ValidationError(
        `Signing threshold ${ktSize} out of range [1, ${keys.length}]`,
      );
    }

    if (nextDigests.length > 0) {
      const ntSize = typeof nt === "string" ? parseInt(nt, 10) : thresholdSize(nt);
      if (ntSize < 0 || ntSize > nextDigests.length) {
        throw new ValidationError(
          `Next threshold ${ntSize} out of range [0, ${nextDigests.length}]`,
        );
      }
    }

    // No duplicate witnesses
    if (new Set(witnessList).size !== witnessList.length) {
      throw new ValidationError("Duplicate witnesses in inception event");
    }

    // TOAD bounds
    if (witnessList.length === 0) {
      if (bt !== 0) {
        throw new ValidationError("TOAD must be 0 when witness list is empty");
      }
    } else {
      if (bt < 1 || bt > witnessList.length) {
        throw new ValidationError(
          `TOAD ${bt} out of range [1, ${witnessList.length}]`,
        );
      }
    }

    // Non-transferable checks
    const isNonTransferable = nextDigests.length === 0;
    if (isNonTransferable) {
      if (witnessList.length > 0) {
        throw new ValidationError(
          "Non-transferable identifier must not have witnesses",
        );
      }
      if (anchors && anchors.length > 0) {
        throw new ValidationError(
          "Non-transferable identifier must not have anchors",
        );
      }
    }

    // Parse config traits
    const traits = parseTraits(configTraitsList);

    // Apply state
    this.prefix = prefix;
    this.transferable = !isNonTransferable;
    this.sequenceNumber = 0;
    this.latestEventSaid = said;
    this.eventIlk = ilk;
    this.signingKeys = keys;
    this.signingThreshold = kt;
    this.nextKeyDigests = nextDigests;
    this.nextThreshold = nt;
    this.witnesses = witnessList;
    this.witnessThreshold = bt;
    this.witnessCuts = [];
    this.witnessAdds = [];
    this.isEstablishmentOnly = traits.estOnly;
    this.isDoNotDelegate = traits.doNotDelegate;
    this.configTraits = configTraitsList;
    this.lastEstablishment = { sn: 0, digest: said };
    this.priorSaid = "";

    if (ilk === Ilk.DelegatedInception) {
      this.isDelegated = true;
      this.delegatorPrefix = fields.di as string;
    }
  }

  /**
   * Apply a non-inception event (rotation, interaction, delegated rotation).
   */
  applyEvent(fields: Record<string, unknown>): void {
    const ilk = fields.t as string;
    const sn = parseInt(fields.s as string, 16);
    const prior = fields.p as string;
    const said = fields.d as string;

    if (ilk === Ilk.Interaction) {
      this.applyInteraction(sn, prior, said);
    } else if (ROTATION_ILKS.has(ilk as Ilk)) {
      this.applyRotation(fields, sn, prior, said, ilk);
    } else {
      throw new ValidationError(`Cannot update with ilk "${ilk}"`);
    }
  }

  private applyInteraction(sn: number, prior: string, said: string): void {
    if (this.isEstablishmentOnly) {
      throw new ValidationError(
        "Interaction events not allowed with EstablishmentOnly (EO) trait",
      );
    }
    if (sn !== this.sequenceNumber + 1) {
      throw new ValidationError(
        `Expected sn ${this.sequenceNumber + 1} for interaction, got ${sn}`,
      );
    }
    if (prior !== this.latestEventSaid) {
      throw new ValidationError(
        `Prior SAID mismatch: expected "${this.latestEventSaid}", got "${prior}"`,
      );
    }
    this.sequenceNumber = sn;
    this.latestEventSaid = said;
    this.eventIlk = Ilk.Interaction;
    this.priorSaid = prior;
  }

  private applyRotation(
    fields: Record<string, unknown>,
    sn: number,
    prior: string,
    said: string,
    ilk: string,
  ): void {
    // Non-transferable check
    if (!this.transferable) {
      throw new ValidationError("Cannot rotate a non-transferable identifier");
    }

    // Sequence validation (supports recovery)
    if (sn === this.sequenceNumber + 1) {
      if (prior !== this.latestEventSaid) {
        throw new ValidationError(
          `Prior SAID mismatch: expected "${this.latestEventSaid}", got "${prior}"`,
        );
      }
    } else if (sn > this.sequenceNumber + 1) {
      throw new OutOfOrderError(
        `Out of order: expected sn <= ${this.sequenceNumber + 1}, got ${sn}`,
        this.prefix,
        sn,
      );
    } else if (isValidSupersede(ilk, sn, this.sequenceNumber, this.lastEstablishment.sn)) {
      // Valid recovery rotation
    } else {
      throw new ValidationError(
        `Invalid rotation sn ${sn} for current state (sn=${this.sequenceNumber}, lastEst.s=${this.lastEstablishment.sn})`,
      );
    }

    const keys = fields.k as string[];
    const kt = fields.kt as Threshold;
    const nextDigests = fields.n as string[];
    const nt = fields.nt as Threshold;
    const bt = parseInt(fields.bt as string, 16);
    const br = fields.br as string[];
    const ba = fields.ba as string[];

    // Threshold validation
    const ktSize = typeof kt === "string" ? parseInt(kt, 10) : thresholdSize(kt);
    if (ktSize < 1 || ktSize > keys.length) {
      throw new ValidationError(
        `Signing threshold ${ktSize} out of range [1, ${keys.length}]`,
      );
    }

    if (nextDigests.length > 0) {
      const ntSize = typeof nt === "string" ? parseInt(nt, 10) : thresholdSize(nt);
      if (ntSize < 0 || ntSize > nextDigests.length) {
        throw new ValidationError(
          `Next threshold ${ntSize} out of range [0, ${nextDigests.length}]`,
        );
      }
    }

    // Derive new witness list
    const newWitnesses = deriveBacks(this.witnesses, br, ba);

    // TOAD validation on new witness list
    if (newWitnesses.length === 0) {
      if (bt !== 0) {
        throw new ValidationError("TOAD must be 0 when witness list is empty");
      }
    } else {
      if (bt < 1 || bt > newWitnesses.length) {
        throw new ValidationError(
          `TOAD ${bt} out of range [1, ${newWitnesses.length}]`,
        );
      }
    }

    // Atomic state update
    this.sequenceNumber = sn;
    this.latestEventSaid = said;
    this.eventIlk = ilk;
    this.priorSaid = prior;
    this.signingKeys = keys;
    this.signingThreshold = kt;
    this.nextKeyDigests = nextDigests;
    this.nextThreshold = nt;
    this.witnesses = newWitnesses;
    this.witnessThreshold = bt;
    this.witnessCuts = br;
    this.witnessAdds = ba;
    this.lastEstablishment = { sn, digest: said };
    this.transferable = nextDigests.length > 0;
  }

  /**
   * Persist the validated event and associated data to the repository.
   */
  async commitEvent(
    raw: Uint8Array,
    fields: Record<string, unknown>,
    signatures: IndexedSiger[],
    witnessSignatures: IndexedSiger[],
    repository: EventRepository,
    options: {
      firstSeenOrdinal?: number;
      firstSeenDatetime?: string;
      local?: boolean;
      readOnly?: boolean;
      delegatorSeqNum?: number;
      delegatorDigest?: string;
    } = {},
  ): Promise<{ firstSeenOrdinal: number; datetime: string }> {
    const prefix = fields.i as string;
    const said = fields.d as string;
    const sn = parseInt(fields.s as string, 16);

    // 1. Store serialized event
    await repository.storeEvent(prefix, said, raw);

    // 2. Append to KEL index
    await repository.appendToEventLog(prefix, sn, said);

    // 3. First-seen log + ordinal
    let fn: number;
    let datetime: string;

    if (options.readOnly) {
      fn = options.firstSeenOrdinal ?? 0;
      datetime = options.firstSeenDatetime ?? new Date().toISOString();
    } else {
      fn = options.firstSeenOrdinal ?? await repository.appendToFirstSeenLog(prefix, said);
      datetime = options.firstSeenDatetime ?? new Date().toISOString();
      await repository.storeFirstSeenOrdinal(prefix, said, fn);
      await repository.storeDatetime(prefix, said, datetime);
    }

    this.firstSeenOrdinal = fn;
    this.firstSeenDatetime = datetime;

    // 4. Store controller signatures
    if (signatures.length > 0) {
      await repository.storeControllerSignatures(prefix, said, signatures);
    }

    // 5. Store witness signatures
    if (witnessSignatures.length > 0) {
      await repository.storeWitnessSignatures(prefix, said, witnessSignatures);
    }

    // 6. Store provenance
    await repository.storeProvenance(prefix, said, { local: options.local ?? false });

    // 7. Store delegation seal if delegated
    if (options.delegatorSeqNum !== undefined && options.delegatorDigest) {
      await repository.storeDelegationSeal(
        prefix,
        said,
        options.delegatorSeqNum,
        options.delegatorDigest,
      );
    }

    // 8. Store witness state at establishment events
    if (ESTABLISHMENT_ILKS.has(fields.t as Ilk)) {
      await repository.storeWitnessState(prefix, said, this.witnesses);
    }

    // 9. Store key state snapshot
    const snap = this.snapshot();
    await repository.storeKeyStateSnapshot(prefix, snap);

    return { firstSeenOrdinal: fn, datetime };
  }

  /**
   * Export the current key state as a serializable KeyStateSnapshot.
   */
  snapshot(): KeyStateSnapshot {
    const ee: EstablishmentDetail = {
      s: this.lastEstablishment.sn.toString(16),
      d: this.lastEstablishment.digest,
      br: this.witnessCuts,
      ba: this.witnessAdds,
    };

    return {
      vn: [1, 0],
      i: this.prefix,
      s: this.sequenceNumber.toString(16),
      p: this.priorSaid,
      d: this.latestEventSaid,
      f: this.firstSeenOrdinal.toString(16),
      dt: this.firstSeenDatetime || new Date().toISOString(),
      et: this.eventIlk,
      kt: this.signingThreshold,
      k: this.signingKeys,
      nt: this.nextThreshold,
      n: this.nextKeyDigests,
      bt: this.witnessThreshold.toString(16),
      b: this.witnesses,
      c: this.configTraits,
      ee,
      di: this.delegatorPrefix,
    };
  }
}
