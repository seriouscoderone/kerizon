import { saidify } from "cesr-ts";
import type { HashFn } from "cesr-ts";
import { SAID_FIELDS } from "./schemas.js";
import { INCEPTION_ILKS } from "../../types/EventTypes.js";
import type { Ilk } from "../../types/EventTypes.js";

/** Default SHA-256 hash function for SAID computation (production should use Blake3). */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest("SHA-256", data.slice());
  return new Uint8Array(hash);
}

/**
 * Synchronous SHA-256 is not available in Web Crypto, so we provide a
 * wrapper that the caller can replace with a sync Blake3 implementation.
 * For saidify, cesr-ts requires a synchronous HashFn.
 */
export type SyncHashFn = HashFn;

/**
 * Compute the SAID(s) for an event, returning the finalized fields and serialized bytes.
 *
 * For inception events (icp/dip), both `d` and `i` are SAIDs.
 * For other events, only `d` is a SAID.
 * For receipts (rct), no SAID computation is needed.
 *
 * @param fields - Event fields object (will be cloned, not mutated)
 * @param hashFn - Synchronous hash function for SAID computation
 * @returns The finalized fields and serialized event bytes
 */
export function computeSaid(
  fields: Record<string, unknown>,
  hashFn: SyncHashFn,
): { fields: Record<string, unknown>; raw: Uint8Array } {
  const ilk = fields.t as string;
  const saidFieldNames = SAID_FIELDS[ilk];

  if (!saidFieldNames || saidFieldNames.length === 0) {
    // Receipt or unknown — no SAID computation, just serialize
    const raw = new TextEncoder().encode(JSON.stringify(fields));
    return { fields: { ...fields }, raw };
  }

  if (!INCEPTION_ILKS.has(ilk as Ilk)) {
    // Single SAID field (d) — standard saidify
    const result = saidify({ ...fields }, hashFn);
    return { fields: result.ked, raw: result.raw };
  }

  // Dual SAID (icp/dip): both d and i must be the same SAID
  // Set both as placeholder, compute SAID, then set i = said
  const cloned = { ...fields };
  const dummySize = 44; // Blake3-256 / SHA-256 SAID length in qb64
  cloned.d = "#".repeat(dummySize);
  cloned.i = "#".repeat(dummySize);
  const result = saidify(cloned, hashFn);
  result.ked.i = result.said;
  // Re-serialize with the final i value
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
