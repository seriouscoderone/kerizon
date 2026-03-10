import type { HashFn } from "cesr-ts";
import type { Seal, KeyStateSnapshot } from "../types.js";
import { ValidationError } from "../errors.js";
import { computeSaid, buildEventWithVersion } from "./_event-utils.js";
import { BuiltEvent } from "./signed-event.js";

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

  /** Populate builder fields from an existing key state snapshot. */
  fromKeyState(state: KeyStateSnapshot): this {
    this._identifier = state.i;
    this._sequenceNumber = parseInt(state.s, 16) + 1;
    this._previousEvent = state.d;
    return this;
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
      throw new ValidationError("Identifier is required for interaction");
    }
    if (this._sequenceNumber < 1) {
      throw new ValidationError("Interaction sequence number must be >= 1");
    }
    if (!this._previousEvent) {
      throw new ValidationError("Previous event SAID is required");
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

    return new BuiltEvent({
      fields: finalFields,
      raw,
      prefix: this._identifier,
      said: finalFields.d as string,
      sn: this._sequenceNumber,
      ilk: "ixn",
    });
  }
}
