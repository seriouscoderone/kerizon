import { describe, it, expect } from "vitest";
import { deriveBacks } from "../../../src/core/events/deriveBacks.js";
import { WitnessError } from "../../../src/types/errors.js";

describe("deriveBacks", () => {
  it("adds witnesses to empty list", () => {
    expect(deriveBacks([], [], ["w1", "w2"])).toEqual(["w1", "w2"]);
  });

  it("removes witnesses", () => {
    expect(deriveBacks(["w1", "w2", "w3"], ["w2"], [])).toEqual(["w1", "w3"]);
  });

  it("adds and removes witnesses", () => {
    expect(deriveBacks(["w1", "w2", "w3"], ["w3"], ["w4"])).toEqual([
      "w1",
      "w2",
      "w4",
    ]);
  });

  it("no-op when both empty", () => {
    expect(deriveBacks(["w1", "w2"], [], [])).toEqual(["w1", "w2"]);
  });

  it("rejects duplicate removes", () => {
    expect(() => deriveBacks(["w1", "w2"], ["w1", "w1"], [])).toThrow(
      WitnessError,
    );
  });

  it("rejects duplicate adds", () => {
    expect(() => deriveBacks(["w1"], [], ["w2", "w2"])).toThrow(WitnessError);
  });

  it("rejects removing a witness not in current list", () => {
    expect(() => deriveBacks(["w1"], ["w2"], [])).toThrow(WitnessError);
  });

  it("rejects same witness in br and ba", () => {
    expect(() => deriveBacks(["w1", "w2"], ["w1"], ["w1"])).toThrow(
      WitnessError,
    );
  });

  it("rejects adding a witness already in current list", () => {
    expect(() => deriveBacks(["w1", "w2"], [], ["w1"])).toThrow(WitnessError);
  });

  it("preserves order: removes from position, appends adds", () => {
    const result = deriveBacks(["w1", "w2", "w3"], ["w1"], ["w4"]);
    expect(result).toEqual(["w2", "w3", "w4"]);
  });
});
