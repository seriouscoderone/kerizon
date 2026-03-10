import { describe, it, expect } from "vitest";
import {
  isValidSupersede,
  delegationSealSupersedes,
} from "../../../src/core/delegation/supersedingRules.js";

describe("isValidSupersede — A-rules (non-delegated)", () => {
  it("rot supersedes ixn when lastEst.s < sn <= kever.sn", () => {
    // lastEst.s=0, sn=1, kever.sn=3
    expect(isValidSupersede("rot", 1, 3, 0, "ixn")).toBe(true);
  });

  it("rot does NOT supersede another rot (Rule A1)", () => {
    expect(isValidSupersede("rot", 1, 3, 0, "rot")).toBe(false);
  });

  it("ixn does NOT supersede any event (Rule A2)", () => {
    expect(isValidSupersede("ixn", 1, 3, 0, "ixn")).toBe(false);
  });

  it("rot does not supersede when sn <= lastEst.s", () => {
    // lastEst.s=2, sn=2: not strictly greater
    expect(isValidSupersede("rot", 2, 3, 2)).toBe(false);
  });

  it("rot does not supersede when sn > kever.sn", () => {
    expect(isValidSupersede("rot", 5, 3, 0)).toBe(false);
  });
});

describe("isValidSupersede — B-rules (delegated)", () => {
  it("drt supersedes when lastEst.s <= sn <= kever.sn", () => {
    expect(isValidSupersede("drt", 2, 3, 2)).toBe(true);
  });

  it("drt supersedes at sn == lastEst.s (more permissive than rot)", () => {
    expect(isValidSupersede("drt", 1, 3, 1)).toBe(true);
  });

  it("drt does not supersede when sn > kever.sn", () => {
    expect(isValidSupersede("drt", 5, 3, 0)).toBe(false);
  });
});

describe("delegationSealSupersedes", () => {
  it("new seal at higher delegator sn supersedes", () => {
    expect(delegationSealSupersedes(5, "ENEW", 3, "EOLD")).toBe(true);
  });

  it("same delegator sn does not supersede by default", () => {
    expect(delegationSealSupersedes(3, "ENEW", 3, "EOLD")).toBe(false);
  });

  it("lower delegator sn does not supersede", () => {
    expect(delegationSealSupersedes(2, "ENEW", 3, "EOLD")).toBe(false);
  });
});
