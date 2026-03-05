import type { HashFn } from "cesr-ts";
import type { ICryptoProvider } from "../../interfaces/ICryptoProvider.js";
import type { Threshold } from "../../types/EventTypes.js";
import type { KeyStateRecord, StateEstEvent } from "../../types/KeyStateRecord.js";
import {
  Ilk,
  ESTABLISHMENT_ILKS,
  INCEPTION_ILKS,
  ROTATION_ILKS,
} from "../../types/EventTypes.js";
import {
  StructuralError,
  SequenceError,
  ConfigError,
  WitnessError,
} from "../../types/errors.js";
import { parseTraits } from "../events/configTraits.js";
import { deriveBacks } from "../events/deriveBacks.js";
import { thresholdSize } from "../signature/satisfyThreshold.js";

/**
 * Kever — the Key Event Verifier for a single AID.
 *
 * Maintains verified key state and provides methods to apply
 * inception, rotation, and interaction events.
 */
export class Kever {
  /** AID prefix. */
  prefix: string = "";
  /** Whether the identifier is transferable (has next-key digests). */
  transferable: boolean = false;

  /** Sequence number of latest event. */
  sn: number = 0;
  /** First-seen ordinal of latest event. */
  fn: number = 0;
  /** SAID of latest event. */
  lastSaid: string = "";
  /** Ilk of latest event. */
  lastIlk: string = "";

  /** Current signing keys (qb64). */
  signingKeys: string[] = [];
  /** Current signing threshold. */
  signingThreshold: Threshold = "0";

  /** Next key digests (qb64). */
  nextKeyDigests: string[] = [];
  /** Next rotation threshold. */
  nextKeyThreshold: Threshold = "0";

  /** Current witness AID prefixes. */
  witnesses: string[] = [];
  /** Witness threshold (TOAD). */
  toad: number = 0;
  /** Witnesses removed in latest est event. */
  lastCuts: string[] = [];
  /** Witnesses added in latest est event. */
  lastAdds: string[] = [];

  /** Whether this is a delegated identifier. */
  delegated: boolean = false;
  /** Delegator prefix (empty if not delegated). */
  delegatorPrefix: string = "";

  /** EO trait active. */
  estOnly: boolean = false;
  /** DND trait active. */
  doNotDelegate: boolean = false;

  /** Configuration traits. */
  configTraits: string[] = [];

  /** Sequence number and SAID of last establishment event. */
  lastEst: { s: number; d: string } = { s: 0, d: "" };

  /** Prior event SAID (for chain linking). */
  priorSaid: string = "";

  /** First-seen datetime. */
  datetime: string = "";

  /**
   * Initialize a Kever from an inception event.
   */
  incept(fields: Record<string, unknown>): void {
    const ilk = fields.t as string;
    if (!INCEPTION_ILKS.has(ilk as Ilk)) {
      throw new StructuralError(`Expected inception ilk, got "${ilk}"`);
    }

    const sn = parseInt(fields.s as string, 16);
    if (sn !== 0) {
      throw new SequenceError("Inception event must have sn = 0");
    }

    const keys = fields.k as string[];
    const kt = fields.kt as Threshold;
    const nextDigests = fields.n as string[];
    const nt = fields.nt as Threshold;
    const witnesses = fields.b as string[];
    const bt = parseInt(fields.bt as string, 16);
    const configTraitsList = fields.c as string[];
    const anchors = fields.a as unknown[];
    const prefix = fields.i as string;
    const said = fields.d as string;

    // Validate threshold bounds
    const ktSize = typeof kt === "string" ? parseInt(kt, 10) : thresholdSize(kt);
    if (ktSize < 1 || ktSize > keys.length) {
      throw new StructuralError(
        `Signing threshold ${ktSize} out of range [1, ${keys.length}]`,
      );
    }

    if (nextDigests.length > 0) {
      const ntSize = typeof nt === "string" ? parseInt(nt, 10) : thresholdSize(nt);
      if (ntSize < 0 || ntSize > nextDigests.length) {
        throw new StructuralError(
          `Next threshold ${ntSize} out of range [0, ${nextDigests.length}]`,
        );
      }
    }

    // No duplicate witnesses
    if (new Set(witnesses).size !== witnesses.length) {
      throw new WitnessError("Duplicate witnesses in inception event");
    }

    // TOAD bounds
    if (witnesses.length === 0) {
      if (bt !== 0) {
        throw new WitnessError("TOAD must be 0 when witness list is empty");
      }
    } else {
      if (bt < 1 || bt > witnesses.length) {
        throw new WitnessError(
          `TOAD ${bt} out of range [1, ${witnesses.length}]`,
        );
      }
    }

    // Non-transferable checks
    const isNonTransferable = nextDigests.length === 0;
    if (isNonTransferable) {
      // Non-transferable prefixes also use code 'B'
      if (witnesses.length > 0) {
        throw new StructuralError(
          "Non-transferable identifier must not have witnesses",
        );
      }
      if (anchors && anchors.length > 0) {
        throw new StructuralError(
          "Non-transferable identifier must not have anchors",
        );
      }
    }

    // Parse config traits
    const traits = parseTraits(configTraitsList);

    // Apply state
    this.prefix = prefix;
    this.transferable = !isNonTransferable;
    this.sn = 0;
    this.lastSaid = said;
    this.lastIlk = ilk;
    this.signingKeys = keys;
    this.signingThreshold = kt;
    this.nextKeyDigests = nextDigests;
    this.nextKeyThreshold = nt;
    this.witnesses = witnesses;
    this.toad = bt;
    this.lastCuts = [];
    this.lastAdds = [];
    this.estOnly = traits.estOnly;
    this.doNotDelegate = traits.doNotDelegate;
    this.configTraits = configTraitsList;
    this.lastEst = { s: 0, d: said };
    this.priorSaid = "";

    // Delegation
    if (ilk === Ilk.dip) {
      this.delegated = true;
      this.delegatorPrefix = fields.di as string;
    }
  }

  /**
   * Update key state from a rotation or interaction event.
   */
  update(fields: Record<string, unknown>): void {
    const ilk = fields.t as string;
    const sn = parseInt(fields.s as string, 16);
    const prior = fields.p as string;
    const said = fields.d as string;

    if (ilk === Ilk.ixn) {
      this.applyInteraction(fields, sn, prior, said);
    } else if (ROTATION_ILKS.has(ilk as Ilk)) {
      this.applyRotation(fields, sn, prior, said, ilk);
    } else {
      throw new StructuralError(`Cannot update with ilk "${ilk}"`);
    }
  }

  private applyInteraction(
    fields: Record<string, unknown>,
    sn: number,
    prior: string,
    said: string,
  ): void {
    // EO check
    if (this.estOnly) {
      throw new ConfigError(
        "Interaction events not allowed with EstablishmentOnly (EO) trait",
      );
    }

    // Sequence validation: must be exactly next
    if (sn !== this.sn + 1) {
      throw new SequenceError(
        `Expected sn ${this.sn + 1} for interaction, got ${sn}`,
      );
    }

    // Prior digest chain
    if (prior !== this.lastSaid) {
      throw new SequenceError(
        `Prior SAID mismatch: expected "${this.lastSaid}", got "${prior}"`,
      );
    }

    // Update tracking only (key state unchanged)
    this.sn = sn;
    this.lastSaid = said;
    this.lastIlk = Ilk.ixn;
    this.priorSaid = prior;
  }

  private applyRotation(
    fields: Record<string, unknown>,
    sn: number,
    prior: string,
    said: string,
    ilk: string,
  ): void {
    // Sequence validation for rotation (supports recovery)
    if (sn === this.sn + 1) {
      // Normal next event
      if (prior !== this.lastSaid) {
        throw new SequenceError(
          `Prior SAID mismatch: expected "${this.lastSaid}", got "${prior}"`,
        );
      }
    } else if (sn > this.sn + 1) {
      throw new SequenceError(
        `Out of order: expected sn <= ${this.sn + 1}, got ${sn}`,
      );
    } else if (ilk === Ilk.rot && this.lastEst.s < sn && sn <= this.sn) {
      // Recovery rotation (non-delegated): lastEst.s < sn <= kever.sn
      // Valid recovery — prior must match event at sn-1
    } else if (ilk === Ilk.drt && this.lastEst.s <= sn && sn <= this.sn) {
      // Recovery rotation (delegated): lastEst.s <= sn <= kever.sn
    } else {
      throw new SequenceError(
        `Invalid rotation sn ${sn} for current state (sn=${this.sn}, lastEst.s=${this.lastEst.s})`,
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
      throw new StructuralError(
        `Signing threshold ${ktSize} out of range [1, ${keys.length}]`,
      );
    }

    if (nextDigests.length > 0) {
      const ntSize = typeof nt === "string" ? parseInt(nt, 10) : thresholdSize(nt);
      if (ntSize < 0 || ntSize > nextDigests.length) {
        throw new StructuralError(
          `Next threshold ${ntSize} out of range [0, ${nextDigests.length}]`,
        );
      }
    }

    // Derive new witness list
    const newWitnesses = deriveBacks(this.witnesses, br, ba);

    // TOAD validation on new witness list
    if (newWitnesses.length === 0) {
      if (bt !== 0) {
        throw new WitnessError("TOAD must be 0 when witness list is empty");
      }
    } else {
      if (bt < 1 || bt > newWitnesses.length) {
        throw new WitnessError(
          `TOAD ${bt} out of range [1, ${newWitnesses.length}]`,
        );
      }
    }

    // Atomic state update
    this.sn = sn;
    this.lastSaid = said;
    this.lastIlk = ilk;
    this.priorSaid = prior;
    this.signingKeys = keys;
    this.signingThreshold = kt;
    this.nextKeyDigests = nextDigests;
    this.nextKeyThreshold = nt;
    this.witnesses = newWitnesses;
    this.toad = bt;
    this.lastCuts = br;
    this.lastAdds = ba;
    this.lastEst = { s: sn, d: said };
    this.transferable = nextDigests.length > 0;
  }

  /**
   * Export a serializable KeyStateRecord snapshot.
   */
  toKeyStateRecord(): KeyStateRecord {
    const ee: StateEstEvent = {
      s: this.lastEst.s.toString(16),
      d: this.lastEst.d,
      br: this.lastCuts,
      ba: this.lastAdds,
    };

    return {
      vn: [1, 0],
      i: this.prefix,
      s: this.sn.toString(16),
      p: this.priorSaid,
      d: this.lastSaid,
      f: this.fn.toString(16),
      dt: this.datetime || new Date().toISOString(),
      et: this.lastIlk,
      kt: this.signingThreshold,
      k: this.signingKeys,
      nt: this.nextKeyThreshold,
      n: this.nextKeyDigests,
      bt: this.toad.toString(16),
      b: this.witnesses,
      c: this.configTraits,
      ee,
      di: this.delegatorPrefix,
    };
  }
}
