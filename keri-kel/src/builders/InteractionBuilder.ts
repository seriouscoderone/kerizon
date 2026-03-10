import type { HashFn } from "cesr-ts";
import type { Seal } from "../types/EventTypes.js";
import { StructuralError, SequenceError } from "../types/errors.js";
import { computeSaid, buildEventWithVersion } from "../core/events/computeSaid.js";
import type { BuiltEvent } from "../pipeline/SignedEvent.js";

/**
 * Fluent builder for interaction events (ixn).
 */
export class InteractionBuilder {
  private _identifier: string = "";
  private _previousEvent: string = "";
  private _sequenceNumber: number = 0;
  private _anchors: Seal[] = [];
  private _hashFn: HashFn;

  constructor(hashFn: HashFn) {
    this._hashFn = hashFn;
  }

  identifier(prefix: string): this {
    this._identifier = prefix;
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

  anchoredSeals(seals: Seal[]): this {
    this._anchors = seals;
    return this;
  }

  build(): BuiltEvent {
    if (!this._identifier) {
      throw new StructuralError("Identifier is required for interaction");
    }
    if (this._sequenceNumber < 1) {
      throw new SequenceError("Interaction sequence number must be >= 1");
    }
    if (!this._previousEvent) {
      throw new StructuralError("Previous event SAID is required");
    }

    const fields = buildEventWithVersion({
      t: "ixn",
      d: "",
      i: this._identifier,
      s: this._sequenceNumber.toString(16),
      p: this._previousEvent,
      a: this._anchors,
    });

    const { fields: finalFields, raw } = computeSaid(fields, this._hashFn);

    return {
      fields: finalFields,
      raw,
      prefix: this._identifier,
      said: finalFields.d as string,
      sn: this._sequenceNumber,
      ilk: "ixn",
    };
  }
}
