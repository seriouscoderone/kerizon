import type { HashFn } from "cesr-ts";
import type { Seal, Threshold, KeyStateSnapshot } from "../types.js";
import { ValidationError } from "../errors.js";
import { computeSaid, buildEventWithVersion } from "./_event-utils.js";
import { ample } from "./_ample.js";
import { BuiltEvent } from "./signed-event.js";

/**
 * Fluent builder for rotation events (rot).
 */
export class RotationBuilder {
  private _identifier: string = "";
  private _signingKeys: string[] = [];
  private _signingThreshold?: Threshold;
  private _previousEvent: string = "";
  private _sequenceNumber: number = 0;
  private _nextKeys: string[] = [];
  private _nextKeyThreshold?: Threshold;
  private _cutWitnesses: string[] = [];
  private _addWitnesses: string[] = [];
  private _witnessThreshold?: number;
  private _anchors: Seal[] = [];
  private _hashFn: HashFn;
  private _currentWitnesses: string[] = [];

  constructor(hashFn: HashFn) {
    this._hashFn = hashFn;
  }

  /** Populate builder fields from an existing key state snapshot. */
  fromKeyState(state: KeyStateSnapshot): this {
    this._identifier = state.i;
    this._sequenceNumber = parseInt(state.s, 16) + 1;
    this._previousEvent = state.d;
    this._currentWitnesses = state.b;
    return this;
  }

  identifier(prefix: string): this {
    this._identifier = prefix;
    return this;
  }

  signingKeys(keys: string[]): this {
    this._signingKeys = keys;
    return this;
  }

  signingThreshold(threshold: Threshold): this {
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

  nextKeyThreshold(threshold: Threshold): this {
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

  currentWitnesses(wits: string[]): this {
    this._currentWitnesses = wits;
    return this;
  }

  build(): BuiltEvent {
    if (!this._identifier) {
      throw new ValidationError("Identifier is required for rotation");
    }
    if (this._signingKeys.length === 0) {
      throw new ValidationError("At least one signing key is required");
    }
    if (this._sequenceNumber < 1) {
      throw new ValidationError("Rotation sequence number must be >= 1");
    }
    if (!this._previousEvent) {
      throw new ValidationError("Previous event SAID is required");
    }

    const kt =
      this._signingThreshold ??
      Math.ceil(this._signingKeys.length / 2).toString();
    const nt =
      this._nextKeyThreshold ??
      (this._nextKeys.length > 0
        ? Math.ceil(this._nextKeys.length / 2).toString()
        : "0");

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

    return new BuiltEvent({
      fields: finalFields,
      raw,
      prefix: this._identifier,
      said: finalFields.d as string,
      sn: this._sequenceNumber,
      ilk: "rot",
    });
  }
}
