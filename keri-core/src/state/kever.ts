/**
 * Kever — immutable per-AID key state holder.
 *
 * Each state transition (establishment or interaction event) returns a new
 * Kever instance. The original is never mutated.
 */

import type { Serder } from '@kerizon/cesr';
import { TraitDex } from './traits.js';

export class Kever {
  readonly prefix: string;
  readonly sn: number;
  readonly currentKeys: string[];
  readonly signingThreshold: string;
  readonly nextDigests: string[];
  readonly nextThreshold: string;
  readonly witnesses: string[];
  readonly witnessThreshold: number;
  readonly configTraits: string[];
  readonly transferable: boolean;
  readonly lastEstSn: number;
  readonly lastEstSaid: string;
  readonly delegator?: string;

  private constructor(init: {
    prefix: string;
    sn: number;
    currentKeys: string[];
    signingThreshold: string;
    nextDigests: string[];
    nextThreshold: string;
    witnesses: string[];
    witnessThreshold: number;
    configTraits: string[];
    transferable: boolean;
    lastEstSn: number;
    lastEstSaid: string;
    delegator?: string;
  }) {
    this.prefix = init.prefix;
    this.sn = init.sn;
    this.currentKeys = init.currentKeys;
    this.signingThreshold = init.signingThreshold;
    this.nextDigests = init.nextDigests;
    this.nextThreshold = init.nextThreshold;
    this.witnesses = init.witnesses;
    this.witnessThreshold = init.witnessThreshold;
    this.configTraits = init.configTraits;
    this.transferable = init.transferable;
    this.lastEstSn = init.lastEstSn;
    this.lastEstSaid = init.lastEstSaid;
    this.delegator = init.delegator;
  }

  /**
   * Create a Kever from an inception event (icp or dip).
   *
   * For self-addressing identifiers, `i === d` (SAID-based prefix).
   * For basic (non-transferable) identifiers, `i` is the verfer qb64
   * (e.g. B-code Ed25519N) and differs from `d`.
   */
  static fromInception(serder: Serder): Kever {
    const ked = serder.ked;
    const nextDigests = ked['n'] as string[];

    return new Kever({
      prefix: serder.pre,
      sn: 0,
      currentKeys: ked['k'] as string[],
      signingThreshold: ked['kt'] as string,
      nextDigests,
      nextThreshold: ked['nt'] as string,
      witnesses: (ked['b'] as string[]) ?? [],
      witnessThreshold: parseInt(ked['bt'] as string, 16),
      configTraits: (ked['c'] as string[]) ?? [],
      transferable: nextDigests.length > 0,
      lastEstSn: 0,
      lastEstSaid: serder.said,
      delegator: ked['di'] as string | undefined,
    });
  }

  /**
   * Apply an establishment event (rot or drt) to produce a new Kever.
   *
   * Updates keys, thresholds, witnesses, and config traits.
   * Witnesses are computed as: `(prior witnesses - br) + ba`.
   * Config traits are cumulative and irreversible.
   */
  applyEstablishment(serder: Serder): Kever {
    const ked = serder.ked;
    const nextDigests = ked['n'] as string[];

    // Compute new witness list: remove br, then append ba
    const witnessesToRemove = new Set((ked['br'] as string[]) ?? []);
    const witnessesToAdd = (ked['ba'] as string[]) ?? [];
    const updatedWitnesses = this.witnesses.filter(
      (w) => !witnessesToRemove.has(w),
    );
    updatedWitnesses.push(...witnessesToAdd);

    // Config traits are cumulative: merge existing with new
    const newTraits = (ked['c'] as string[]) ?? [];
    const mergedTraits = [...this.configTraits];
    for (const trait of newTraits) {
      if (!mergedTraits.includes(trait)) {
        mergedTraits.push(trait);
      }
    }

    return new Kever({
      prefix: this.prefix,
      sn: serder.sn,
      currentKeys: ked['k'] as string[],
      signingThreshold: ked['kt'] as string,
      nextDigests,
      nextThreshold: ked['nt'] as string,
      witnesses: updatedWitnesses,
      witnessThreshold: parseInt(ked['bt'] as string, 16),
      configTraits: mergedTraits,
      transferable: nextDigests.length > 0,
      lastEstSn: serder.sn,
      lastEstSaid: serder.said,
      delegator: this.delegator,
    });
  }

  /**
   * Apply an interaction event (ixn) to produce a new Kever.
   *
   * Only the sequence number changes. All other state is preserved.
   * Throws if the identifier is establishment-only (EO trait).
   */
  applyInteraction(serder: Serder): Kever {
    if (this.configTraits.includes(TraitDex.EstOnly)) {
      throw new Error(
        'Establishment-only identifier: interaction events not allowed',
      );
    }

    return new Kever({
      prefix: this.prefix,
      sn: serder.sn,
      currentKeys: this.currentKeys,
      signingThreshold: this.signingThreshold,
      nextDigests: this.nextDigests,
      nextThreshold: this.nextThreshold,
      witnesses: this.witnesses,
      witnessThreshold: this.witnessThreshold,
      configTraits: this.configTraits,
      transferable: this.transferable,
      lastEstSn: this.lastEstSn,
      lastEstSaid: this.lastEstSaid,
      delegator: this.delegator,
    });
  }
}
