/**
 * fast-check arbitraries for CESR primitives.
 * Generates random but structurally valid CESR data for property-based testing.
 */

import fc from 'fast-check';
import { CODE_TABLE, type CodeEntry, type CesrPrimitive } from '../util/cesr-codec.js';

/** All code entries as an array for random selection. */
const ALL_ENTRIES = Object.values(CODE_TABLE);

/** Generate a random code entry from the Master Code Table. */
export const arbCodeEntry: fc.Arbitrary<CodeEntry> = fc.constantFrom(...ALL_ENTRIES);

/** Generate raw bytes of exactly the specified length. */
export function arbRawBytes(length: number): fc.Arbitrary<Uint8Array> {
  return fc.uint8Array({ minLength: length, maxLength: length });
}

/** Generate a valid CESR primitive: code entry + matching raw bytes. */
export const arbCesrPrimitive: fc.Arbitrary<CesrPrimitive> = arbCodeEntry.chain(entry =>
  arbRawBytes(entry.rawSize).map(raw => ({ entry, raw })),
);

/**
 * Generate a CESR primitive for a specific code.
 * Useful for testing a particular primitive type.
 */
export function arbPrimitiveForCode(code: string): fc.Arbitrary<CesrPrimitive> {
  const entry = CODE_TABLE[code];
  if (!entry) throw new Error(`Unknown code: ${code}`);
  return arbRawBytes(entry.rawSize).map(raw => ({ entry, raw }));
}

/** Generate a stream of 1-N CESR primitives. */
export function arbCesrStream(
  minLength: number = 1,
  maxLength: number = 10,
): fc.Arbitrary<CesrPrimitive[]> {
  return fc.array(arbCesrPrimitive, { minLength, maxLength });
}

/** Generate a valid Ed25519 public key primitive (code 'D'). */
export const arbVerfer: fc.Arbitrary<CesrPrimitive> = arbPrimitiveForCode('D');

/** Generate a valid Ed25519 NT prefix (code 'B'). */
export const arbNtPrefix: fc.Arbitrary<CesrPrimitive> = arbPrimitiveForCode('B');

/** Generate a valid Blake3-256 digest primitive (code 'E'). */
export const arbDigest: fc.Arbitrary<CesrPrimitive> = arbPrimitiveForCode('E');

/** Generate a valid Ed25519 signature primitive (code '0B'). */
export const arbSignature: fc.Arbitrary<CesrPrimitive> = arbPrimitiveForCode('0B');

/** Generate a valid salt primitive (code '0A'). */
export const arbSalt: fc.Arbitrary<CesrPrimitive> = arbPrimitiveForCode('0A');

/** Generate a valid DateTime primitive (code '1AAG'). */
export const arbDateTime: fc.Arbitrary<CesrPrimitive> = arbPrimitiveForCode('1AAG');

/**
 * Generate a digest primitive with one of the supported digest codes.
 */
export const arbDigestAnyAlgo: fc.Arbitrary<CesrPrimitive> = fc.constantFrom(
  'E', 'F', 'G', 'H', '0D',
).chain(code => arbPrimitiveForCode(code));
