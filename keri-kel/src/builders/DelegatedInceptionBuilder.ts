import type { HashFn } from "cesr-ts";
import type { Seal } from "../types/EventTypes.js";
import { StructuralError, WitnessError } from "../types/errors.js";
import { computeSaid, buildEventWithVersion } from "../core/events/computeSaid.js";
import { ample } from "../core/witness/ample.js";
import type { BuiltEvent } from "../pipeline/SignedEvent.js";

/**
 * Fluent builder for delegated inception events (dip).
 * Extends InceptionBuilder with a required delegator field.
 */
export class DelegatedInceptionBuilder {
  private _delegator: string = "";
  private _signingKeys: string[] = [];
  private _signingThreshold?: string | string[][];
  private _nextKeys: string[] = [];
  private _nextKeyThreshold?: string | string[][];
  private _witnesses: string[] = [];
  private _witnessThreshold?: number;
  private _traits: string[] = [];
  private _anchors: Seal[] = [];
  private _hashFn: HashFn;

  constructor(hashFn: HashFn) {
    this._hashFn = hashFn;
  }

  delegator(prefix: string): this {
    this._delegator = prefix;
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

  nextKeys(keys: string[]): this {
    this._nextKeys = keys;
    return this;
  }

  nextKeyThreshold(threshold: string | string[][]): this {
    this._nextKeyThreshold = threshold;
    return this;
  }

  witnesses(wits: string[]): this {
    this._witnesses = wits;
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

  build(): BuiltEvent {
    if (!this._delegator) {
      throw new StructuralError("Delegator prefix is required for dip");
    }
    if (this._signingKeys.length === 0) {
      throw new StructuralError("At least one signing key is required");
    }

    const kt =
      this._signingThreshold ??
      Math.ceil(this._signingKeys.length / 2).toString();
    const nt =
      this._nextKeyThreshold ??
      (this._nextKeys.length > 0
        ? Math.ceil(this._nextKeys.length / 2).toString()
        : "0");

    const bt =
      this._witnessThreshold ??
      (this._witnesses.length > 0 ? ample(this._witnesses.length) : 0);

    const fields = buildEventWithVersion({
      t: "dip",
      d: "",
      i: "",
      s: "0",
      kt,
      k: this._signingKeys,
      nt,
      n: this._nextKeys,
      bt: bt.toString(16),
      b: this._witnesses,
      c: this._traits,
      a: this._anchors,
      di: this._delegator,
    });

    const { fields: finalFields, raw } = computeSaid(fields, this._hashFn);

    return {
      fields: finalFields,
      raw,
      prefix: finalFields.i as string,
      said: finalFields.d as string,
      sn: 0,
      ilk: "dip",
    };
  }
}
