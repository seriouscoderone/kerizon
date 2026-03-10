import { saidify } from "cesr-ts";
import type { HashFn } from "cesr-ts";
import { EVENT_FIELD_ORDER, SAID_FIELDS } from "./schemas.js";
import { Ilk, INCEPTION_ILKS } from "../../types/EventTypes.js";
import { StructuralError } from "../../types/errors.js";

/** Parsed version string components. */
export interface VersionInfo {
  protocol: string;
  major: number;
  minor: number;
  kind: string;
  size: number;
}

/**
 * Parse a KERI version 1.0 version string.
 * Format: "KERI10JSON00012c_" (17 chars)
 */
export function parseVersionString(v: string): VersionInfo {
  if (v.length !== 17 || !v.endsWith("_")) {
    throw new StructuralError(`Invalid version string length or terminator: "${v}"`);
  }
  const protocol = v.slice(0, 4);
  if (protocol !== "KERI") {
    throw new StructuralError(`Unknown protocol: "${protocol}"`);
  }
  const major = parseInt(v.slice(4, 5), 16);
  const minor = parseInt(v.slice(5, 6), 16);
  const kind = v.slice(6, 10);
  if (!["JSON", "CBOR", "MGPK"].includes(kind)) {
    throw new StructuralError(`Unknown serialization kind: "${kind}"`);
  }
  const size = parseInt(v.slice(10, 16), 16);
  if (isNaN(size) || size <= 0) {
    throw new StructuralError(`Invalid size in version string: "${v.slice(10, 16)}"`);
  }
  return { protocol, major, minor, kind, size };
}

/**
 * Validate the structural integrity of a parsed event.
 *
 * Checks:
 * 1. Version string is valid and parseable
 * 2. Field set matches ilk schema (correct fields, correct order)
 * 3. No extra fields (strict mode)
 * 4. SAID in 'd' field matches recomputed digest
 * 5. For inception: prefix in 'i' field matches recomputed SAID
 *
 * @param fields - Parsed event field map
 * @param hashFn - Synchronous hash function for SAID re-computation
 * @param raw - Original serialized bytes (for size check)
 * @throws StructuralError on any validation failure
 */
export function validateStructure(
  fields: Record<string, unknown>,
  hashFn?: HashFn,
  raw?: Uint8Array,
): void {
  // 1. Version string
  const v = fields.v as string;
  if (!v) throw new StructuralError("Missing version string field 'v'");
  const vinfo = parseVersionString(v);

  // Check size matches serialization length
  if (raw && raw.length !== vinfo.size) {
    throw new StructuralError(
      `Version string size (${vinfo.size}) does not match serialized length (${raw.length})`,
    );
  }

  // 2. Field set and order
  const ilk = fields.t as string;
  if (!ilk) throw new StructuralError("Missing event type field 't'");

  const expectedFields = EVENT_FIELD_ORDER[ilk];
  if (!expectedFields) {
    throw new StructuralError(`Unknown event type: "${ilk}"`);
  }

  const actualKeys = Object.keys(fields);
  if (actualKeys.length !== expectedFields.length) {
    throw new StructuralError(
      `Field count mismatch for ${ilk}: expected ${expectedFields.length}, got ${actualKeys.length}`,
    );
  }

  for (let i = 0; i < expectedFields.length; i++) {
    if (actualKeys[i] !== expectedFields[i]) {
      throw new StructuralError(
        `Field order mismatch for ${ilk} at position ${i}: expected "${expectedFields[i]}", got "${actualKeys[i]}"`,
      );
    }
  }

  // 3. SAID binding verification (only if hashFn provided)
  if (hashFn) {
    const saidFields = SAID_FIELDS[ilk];
    if (saidFields && saidFields.length > 0) {
      validateSaidBinding(fields, ilk, hashFn);
    }
  }
}

/**
 * Verify that the SAID field(s) in the event match recomputed digests.
 */
function validateSaidBinding(
  fields: Record<string, unknown>,
  ilk: string,
  hashFn: HashFn,
): void {
  const originalD = fields.d as string;

  if (INCEPTION_ILKS.has(ilk as Ilk)) {
    const originalI = fields.i as string;
    if (originalD !== originalI) {
      throw new StructuralError(
        `Inception SAID mismatch: d="${originalD}" != i="${originalI}"`,
      );
    }
    // Replace both with placeholders and re-saidify
    const cloned = { ...fields };
    cloned.d = "#".repeat(originalD.length);
    cloned.i = "#".repeat(originalI.length);
    const result = saidify(cloned, hashFn);
    if (result.said !== originalD) {
      throw new StructuralError(
        `SAID binding failed: expected "${originalD}", computed "${result.said}"`,
      );
    }
  } else {
    const cloned = { ...fields };
    cloned.d = "#".repeat(originalD.length);
    const result = saidify(cloned, hashFn);
    if (result.said !== originalD) {
      throw new StructuralError(
        `SAID binding failed: expected "${originalD}", computed "${result.said}"`,
      );
    }
  }
}
