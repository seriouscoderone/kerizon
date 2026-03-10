import { buildEventWithVersion } from "./_event-utils.js";
import { BuiltEvent } from "./signed-event.js";

/**
 * Builder for receipt events (rct).
 */
export class ReceiptBuilder {
  private _identifier: string = "";
  private _sequenceNumber: number = 0;
  private _said: string = "";

  forEvent(event: { prefix: string; sn: number; said: string }): this {
    this._identifier = event.prefix;
    this._sequenceNumber = event.sn;
    this._said = event.said;
    return this;
  }

  build(): BuiltEvent {
    const fields = buildEventWithVersion({
      t: "rct",
      d: this._said,
      i: this._identifier,
      s: this._sequenceNumber.toString(16),
    });

    const raw = new TextEncoder().encode(JSON.stringify(fields));

    return new BuiltEvent({
      fields,
      raw,
      prefix: this._identifier,
      said: this._said,
      sn: this._sequenceNumber,
      ilk: "rct",
    });
  }
}
