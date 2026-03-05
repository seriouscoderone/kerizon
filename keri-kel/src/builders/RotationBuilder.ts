import type { HashFn } from "cesr-ts";
import type { Seal } from "../types/EventTypes.js";
import { StructuralError, SequenceError, WitnessError } from "../types/errors.js";
import { computeSaid, buildEventWithVersion } from "../core/events/computeSaid.js";
import { ample } from "../core/witness/ample.js";
import type { BuiltEvent } from "../pipeline/SignedEvent.js";

/**
 * Fluent builder for rotation events (rot).
 */
export class RotationBuilder {
  private _identifier: string = "";
  private _signingKeys: string[] = [];
  private _signingThreshold?: string | string[][];
  private _previousEvent: string = "";
  private _sequenceNumber: number = 0;
  private _nextKeys: string[] = [];
  private _nextKeyThreshold?: string | string[][];
  private _cutWitnesses: string[] = [];
  private _addWitnesses: string[] = [];
  private _witnessThreshold?: number;
  private _anchors: Seal[] = [];
  private _hashFn: HashFn;
  private _currentWitnesses: string[] = [];

  constructor(hashFn: HashFn) {
    this._hashFn = hashFn;
  }

  identifier(prefix: string): this {
    this._identifier = prefix;
    return this;
  }

  signingKeys(keys: string[]): this {
    this._signingKeys = keys;
    return this;
  }

  signingThreshold(threshold: string | string[][]): this {
    this._signingThreshold = threshold;
    return this;
  }

  previousEvent(said: string): this {
    this._previousEvent = said;
    return this;
  }

  sequenceNumber(sn: number): this {
    this._sequenceNumber = sn;
    return this;
  }

  nextKeys(keys: string[]): this {
    this._nextKeys = keys;
    return this;
  }

  nextKeyThreshold(threshold: string | string[][]): this {
    this._nextKeyThreshold = threshold;
    return this;
  }

  cutWitnesses(wits: string[]): this {
    this._cutWitnesses = wits;
    return this;
  }

  addWitnesses(wits: string[]): this {
    this._addWitnesses = wits;
    return this;
  }

  witnessThreshold(toad: number): this {
    this._witnessThreshold = toad;
    return this;
  }

  anchoredSeals(seals: Seal[]): this {
    this._anchors = seals;
    return this;
  }

  /** Set current witnesses (for derivation). */
  currentWitnesses(wits: string[]): this {
    this._currentWitnesses = wits;
    return this;
  }

  build(): BuiltEvent {
    if (!this._identifier) {
      throw new StructuralError("Identifier is required for rotation");
    }
    if (this._signingKeys.length === 0) {
      throw new StructuralError("At least one signing key is required");
    }
    if (this._sequenceNumber < 1) {
      throw new SequenceError("Rotation sequence number must be >= 1");
    }
    if (!this._previousEvent) {
      throw new StructuralError("Previous event SAID is required");
    }

    const kt =
      this._signingThreshold ??
      Math.ceil(this._signingKeys.length / 2).toString();
    const nt =
      this._nextKeyThreshold ??
      (this._nextKeys.length > 0
        ? Math.ceil(this._nextKeys.length / 2).toString()
        : "0");

    // Compute derived witness count for TOAD default
    const derivedWitnessCount =
      this._currentWitnesses.length -
      this._cutWitnesses.length +
      this._addWitnesses.length;
    const bt =
      this._witnessThreshold ??
      (derivedWitnessCount > 0 ? ample(derivedWitnessCount) : 0);

    const fields = buildEventWithVersion({
      t: "rot",
      d: "",
      i: this._identifier,
      s: this._sequenceNumber.toString(16),
      p: this._previousEvent,
      kt,
      k: this._signingKeys,
      nt,
      n: this._nextKeys,
      bt: bt.toString(16),
      br: this._cutWitnesses,
      ba: this._addWitnesses,
      a: this._anchors,
    });

    const { fields: finalFields, raw } = computeSaid(fields, this._hashFn);

    return {
      fields: finalFields,
      raw,
      prefix: this._identifier,
      said: finalFields.d as string,
      sn: this._sequenceNumber,
      ilk: "rot",
    };
  }
}
