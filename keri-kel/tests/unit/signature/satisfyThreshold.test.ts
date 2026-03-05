import { describe, it, expect } from "vitest";
import {
  satisfyThreshold,
  thresholdSize,
} from "../../../src/core/signature/satisfyThreshold.js";

describe("satisfyThreshold — numeric", () => {
  it("satisfies 1-of-1", () => {
    expect(satisfyThreshold("1", [0])).toBe(true);
  });

  it("fails 1-of-1 with no signatures", () => {
    expect(satisfyThreshold("1", [])).toBe(false);
  });

  it("satisfies 2-of-3", () => {
    expect(satisfyThreshold("2", [0, 2])).toBe(true);
  });

  it("fails 2-of-3 with only 1 sig", () => {
    expect(satisfyThreshold("2", [1])).toBe(false);
  });

  it("satisfies 3-of-3", () => {
    expect(satisfyThreshold("3", [0, 1, 2])).toBe(true);
  });

  it("deduplicates indices", () => {
    expect(satisfyThreshold("2", [0, 0, 0])).toBe(false);
  });

  it("returns false for invalid threshold", () => {
    expect(satisfyThreshold("abc", [0])).toBe(false);
  });
});

describe("satisfyThreshold — weighted", () => {
  it("satisfies single clause [1/2, 1/2, 1/4]", () => {
    // Two 1/2 weights = 1.0 >= 1
    expect(satisfyThreshold([["1/2", "1/2", "1/4"]], [0, 1])).toBe(true);
  });

  it("fails single clause with insufficient weight", () => {
    // Only 1/4 < 1
    expect(satisfyThreshold([["1/2", "1/2", "1/4"]], [2])).toBe(false);
  });

  it("satisfies multi-clause threshold", () => {
    // Clause 1 (indices 0-2): 1/2 + 1/2 = 1 ✓
    // Clause 2 (indices 3-4): 1 + 1 = 2 ✓
    expect(
      satisfyThreshold([["1/2", "1/2", "1/4"], ["1", "1"]], [0, 1, 3, 4]),
    ).toBe(true);
  });

  it("fails when one clause is not satisfied", () => {
    // Clause 1: 1/2 >= 1? No
    // Clause 2: 1 + 1 = 2 ✓
    expect(
      satisfyThreshold([["1/2", "1/2", "1/4"], ["1", "1"]], [0, 3, 4]),
    ).toBe(false);
  });

  it("handles whole number weights", () => {
    expect(satisfyThreshold([["1"]], [0])).toBe(true);
    expect(satisfyThreshold([["1"]], [])).toBe(false);
  });

  it("ignores out-of-range indices", () => {
    expect(satisfyThreshold([["1"]], [5])).toBe(false);
  });
});

describe("thresholdSize", () => {
  it("returns numeric value for simple threshold", () => {
    expect(thresholdSize("2")).toBe(2);
  });

  it("returns total positions for weighted threshold", () => {
    expect(thresholdSize([["1/2", "1/2"], ["1"]])).toBe(3);
  });
});
