import type { ICryptoProvider } from "../interfaces/ICryptoProvider.js";
import type { IEventDatabase } from "../interfaces/IEventDatabase.js";
import type { IndexedSiger } from "../core/signature/verifySigs.js";
import type { VerificationResult } from "../types/VerificationResult.js";
import { EscrowReason } from "../types/EscrowReason.js";
import {
  Ilk,
  INCEPTION_ILKS,
  ROTATION_ILKS,
  DELEGATED_ILKS,
} from "../types/EventTypes.js";
import { validateStructure } from "../core/events/validateStructure.js";
import { verifySigs } from "../core/signature/verifySigs.js";
import { satisfyThreshold } from "../core/signature/satisfyThreshold.js";
import { Kever } from "../core/state/Kever.js";
import { StructuralError, SequenceError } from "../types/errors.js";
import type { HashFn } from "cesr-ts";

/** Options for the verification pipeline. */
export interface PipelineOptions {
  db: IEventDatabase;
  crypto: ICryptoProvider;
  hashFn?: HashFn;
  kevers?: Map<string, Kever>;
}

/**
 * 6-stage verification pipeline.
 *
 * Each stage returns Accepted (proceed), Escrowed (retry later), or Rejected (discard).
 * Stages: Structural → Sequence → Key State → Signatures → Delegation → Finalize
 */
export class VerificationPipeline {
  private db: IEventDatabase;
  private crypto: ICryptoProvider;
  private hashFn?: HashFn;
  private kevers: Map<string, Kever>;

  constructor(opts: PipelineOptions) {
    this.db = opts.db;
    this.crypto = opts.crypto;
    this.hashFn = opts.hashFn;
    this.kevers = opts.kevers ?? new Map();
  }

  /**
   * Run all 6 pipeline stages on an event.
   */
  async verify(
    raw: Uint8Array,
    fields: Record<string, unknown>,
    sigers: IndexedSiger[] = [],
  ): Promise<VerificationResult> {
    // Stage 1: STRUCTURAL
    try {
      validateStructure(fields, this.hashFn, raw);
    } catch (e) {
      return {
        type: "rejected",
        errors: [(e as Error).message],
      };
    }

    const prefix = fields.i as string;
    const ilk = fields.t as string;
    const sn = parseInt(fields.s as string, 16);
    const said = fields.d as string;

    // Stage 2: SEQUENCE
    const seqResult = this.checkSequence(prefix, ilk, sn, fields);
    if (seqResult) return seqResult;

    // Stage 3: KEY STATE
    const ksResult = this.checkKeyState(fields, ilk);
    if (ksResult) return ksResult;

    // Stage 4: SIGNATURES
    const sigResult = await this.checkSignatures(raw, fields, ilk, sigers);
    if (sigResult) return sigResult;

    // Stage 5: DELEGATION
    if (DELEGATED_ILKS.has(ilk as Ilk)) {
      const delResult = await this.checkDelegation(fields);
      if (delResult) return delResult;
    }

    // Stage 6: FINALIZE
    return this.finalize(raw, fields, sigers, prefix, sn, said);
  }

  private checkSequence(
    prefix: string,
    ilk: string,
    sn: number,
    fields: Record<string, unknown>,
  ): VerificationResult | null {
    if (INCEPTION_ILKS.has(ilk as Ilk)) {
      if (sn !== 0) {
        return { type: "rejected", errors: ["Inception must have sn = 0"] };
      }
      return null;
    }

    const kever = this.kevers.get(prefix);
    if (!kever) {
      return {
        type: "escrowed",
        reason: EscrowReason.OUT_OF_ORDER,
        message: `No inception found for ${prefix}`,
      };
    }

    if (ilk === Ilk.ixn && kever.estOnly) {
      return {
        type: "rejected",
        errors: ["Interaction events not allowed with EO trait"],
      };
    }

    const expectedSn = kever.sn + 1;
    if (sn > expectedSn) {
      return {
        type: "escrowed",
        reason: EscrowReason.OUT_OF_ORDER,
        message: `Out of order: expected sn <= ${expectedSn}, got ${sn}`,
      };
    }

    return null;
  }

  private checkKeyState(
    fields: Record<string, unknown>,
    ilk: string,
  ): VerificationResult | null {
    if (ilk === Ilk.ixn || ilk === Ilk.rct) return null;

    const keys = fields.k as string[] | undefined;
    const kt = fields.kt as string | string[][] | undefined;
    if (keys && kt) {
      const ktNum =
        typeof kt === "string" ? parseInt(kt, 10) : kt.flat().length;
      if (ktNum < 1 || ktNum > keys.length) {
        return {
          type: "rejected",
          errors: [`Signing threshold ${ktNum} out of range [1, ${keys.length}]`],
        };
      }
    }

    return null;
  }

  private async checkSignatures(
    raw: Uint8Array,
    fields: Record<string, unknown>,
    ilk: string,
    sigers: IndexedSiger[],
  ): Promise<VerificationResult | null> {
    if (ilk === Ilk.rct) return null;

    const keys = fields.k as string[] | undefined;
    const kt = fields.kt as string | string[][] | undefined;

    if (!keys || !kt) {
      // For ixn, use the kever's current keys
      const prefix = fields.i as string;
      const kever = this.kevers.get(prefix);
      if (kever) {
        const result = await verifySigs(this.crypto, raw, sigers, kever.signingKeys);
        if (!satisfyThreshold(kever.signingThreshold, result.verifiedIndices)) {
          return {
            type: "escrowed",
            reason: EscrowReason.PARTIAL_SIGNATURES,
            message: `Insufficient signatures: ${result.verifiedIndices.length} verified`,
          };
        }
      }
      return null;
    }

    if (sigers.length > 0) {
      const result = await verifySigs(this.crypto, raw, sigers, keys);
      if (!satisfyThreshold(kt, result.verifiedIndices)) {
        return {
          type: "escrowed",
          reason: EscrowReason.PARTIAL_SIGNATURES,
          message: `Insufficient signatures: ${result.verifiedIndices.length} verified`,
        };
      }
    }

    return null;
  }

  private async checkDelegation(
    fields: Record<string, unknown>,
  ): Promise<VerificationResult | null> {
    const delegatorPrefix = fields.di as string | undefined;
    if (!delegatorPrefix) return null;

    const delegatorKever = this.kevers.get(delegatorPrefix);
    if (!delegatorKever) {
      return {
        type: "escrowed",
        reason: EscrowReason.PENDING_DELEGATION,
        message: `Delegator ${delegatorPrefix} not found`,
      };
    }

    if (delegatorKever.doNotDelegate) {
      return {
        type: "rejected",
        errors: [`Delegator ${delegatorPrefix} has DND trait`],
      };
    }

    // Full seal lookup deferred to Kevery for now
    return null;
  }

  private async finalize(
    raw: Uint8Array,
    fields: Record<string, unknown>,
    sigers: IndexedSiger[],
    prefix: string,
    sn: number,
    said: string,
  ): Promise<VerificationResult> {
    // Log event
    await this.db.putEvent(prefix, said, raw);
    await this.db.addKelEntry(prefix, sn, said);
    if (sigers.length > 0) {
      await this.db.putSigs(prefix, said, sigers);
    }

    const fn = await this.db.appendFel(prefix, said);
    await this.db.putFn(prefix, said, fn);
    await this.db.putDatetime(prefix, said, new Date().toISOString());

    return {
      type: "accepted",
      prefix,
      sn,
      said,
      fn,
    };
  }
}
