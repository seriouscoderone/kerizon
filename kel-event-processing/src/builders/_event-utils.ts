import { saidify } from "cesr-ts";
import type { HashFn } from "cesr-ts";
import { SAID_FIELDS, INCEPTION_ILKS } from "../types.js";

/**
 * Compute the SAID(s) for an event, returning the finalized fields and serialized bytes.
 *
 * For inception events (icp/dip), both `d` and `i` are SAIDs.
 * For other events, only `d` is a SAID.
 * For receipts (rct), no SAID computation is needed.
 */
export function computeSaid(
  fields: Record<string, unknown>,
  hashFn: HashFn,
): { fields: Record<string, unknown>; raw: Uint8Array } {
  const ilk = fields.t as string;
  const saidFieldNames = SAID_FIELDS[ilk];

  if (!saidFieldNames || saidFieldNames.length === 0) {
    const raw = new TextEncoder().encode(JSON.stringify(fields));
    return { fields: { ...fields }, raw };
  }

  if (!INCEPTION_ILKS.has(ilk as any)) {
    const result = saidify({ ...fields }, hashFn);
    return { fields: result.ked, raw: result.raw };
  }

  // Dual SAID (icp/dip): both d and i must be the same SAID
  const cloned = { ...fields };
  const dummySize = 44;
  cloned.d = "#".repeat(dummySize);
  cloned.i = "#".repeat(dummySize);
  const result = saidify(cloned, hashFn);
  result.ked.i = result.said;
  const raw = new TextEncoder().encode(JSON.stringify(result.ked));
  return { fields: result.ked, raw };
}

/**
 * Build a KERI version 1 JSON version string with the correct size.
 */
export function makeVersionString(size: number): string {
  const sizeHex = size.toString(16).padStart(6, "0");
  return `KERI10JSON${sizeHex}_`;
}

/**
 * Construct event fields with a placeholder version string,
 * then compute the correct version string based on serialized size.
 */
export function buildEventWithVersion(
  fields: Record<string, unknown>,
): Record<string, unknown> {
  const placeholder = "KERI10JSON000000_";
  const withPlaceholder = { v: placeholder, ...fields };
  const json = JSON.stringify(withPlaceholder);
  const size = new TextEncoder().encode(json).length;
  const sizeHex = size.toString(16).padStart(6, "0");
  withPlaceholder.v = `KERI10JSON${sizeHex}_`;
  return withPlaceholder;
}
