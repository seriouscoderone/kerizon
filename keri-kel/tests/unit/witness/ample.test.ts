import { describe, it, expect } from "vitest";
import { ample } from "../../../src/core/witness/ample.js";

describe("ample", () => {
  it("returns 0 for 0 witnesses", () => {
    expect(ample(0)).toBe(0);
  });

  it("returns 1 for 1 witness", () => {
    expect(ample(1)).toBe(1);
  });

  it("returns 2 for 2 witnesses", () => {
    expect(ample(2)).toBe(2);
  });

  it("returns 2 for 3 witnesses", () => {
    expect(ample(3)).toBe(2);
  });

  it("returns 3 for 4 witnesses", () => {
    expect(ample(4)).toBe(3);
  });

  it("returns 4 for 5 witnesses", () => {
    // n=5, f=floor((5-1)/3)=1, ceil((5+1+1)/2)=4
    expect(ample(5)).toBe(4);
  });

  it("returns 4 for 6 witnesses", () => {
    expect(ample(6)).toBe(4);
  });

  it("returns 5 for 7 witnesses", () => {
    expect(ample(7)).toBe(5);
  });

  it("returns 7 for 10 witnesses", () => {
    expect(ample(10)).toBe(7);
  });

  it("allows explicit fault tolerance", () => {
    // n=4, f=0: m = ceil((4+0+1)/2) = 3
    expect(ample(4, 0)).toBe(3);
  });

  it("throws for insufficient witnesses for fault tolerance", () => {
    // f=2 requires n >= 7, but n=5
    expect(() => ample(5, 2)).toThrow();
  });
});
