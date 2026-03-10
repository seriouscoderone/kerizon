import { describe, it, expect } from "vitest";
import { parseSad } from "../../src/core/SadParser.js";
import { makeKeriJson } from "../helpers.js";

describe("SadParser", () => {
  it("parses a minimal KERI rpy message", () => {
    const bytes = makeKeriJson({
      t: "rpy",
      d: "EABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
      dt: "2026-01-01T00:00:00.000000+00:00",
      r: "/end/role/add",
      a: {
        cid: "BAliceAliceAliceAliceAliceAliceAliceAliceAAA",
        role: "mailbox",
        eid: "BMailboxMailboxMailboxMailboxMailboxMailboxA",
      },
    });

    const result = parseSad(bytes);

    expect(result.fields.t).toBe("rpy");
    expect(result.fields.r).toBe("/end/role/add");
    expect((result.fields.a as { role: string }).role).toBe("mailbox");
    expect(result.raw).toBeInstanceOf(Uint8Array);
    expect(result.raw.length).toBeGreaterThan(0);
    expect(result.attachments).toBeInstanceOf(Array);
  });

  it("throws on empty input", () => {
    expect(() => parseSad(new Uint8Array(0))).toThrow();
  });

  it("throws on invalid input", () => {
    expect(() => parseSad(new Uint8Array([1, 2, 3, 4]))).toThrow();
  });

  it("parses a /end/role/cut message", () => {
    const bytes = makeKeriJson({
      t: "rpy",
      d: "EBCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
      r: "/end/role/cut",
      a: {
        cid: "BAliceAliceAliceAliceAliceAliceAliceAliceAAA",
        role: "mailbox",
        eid: "BMailboxMailboxMailboxMailboxMailboxMailboxA",
      },
    });

    const result = parseSad(bytes);
    expect(result.fields.r).toBe("/end/role/cut");
  });

  it("exposes all SAD top-level fields", () => {
    const bytes = makeKeriJson({
      t: "exn",
      d: "ECDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr",
      r: "/fwd",
      q: {},
      a: { msg: "hello" },
    });
    const result = parseSad(bytes);
    expect(result.fields.t).toBe("exn");
    expect(result.fields.r).toBe("/fwd");
    expect(result.fields.q).toEqual({});
  });
});
