/**
 * SAID (Self-Addressing Identifier) computation and verification.
 *
 * The SAID algorithm (5 steps):
 * 1. Choose a digest algorithm (determines CESR code, e.g. 'E' for Blake3-256)
 * 2. Determine the SAID field length from the code's full size (e.g. 44 chars for 'E')
 * 3. Replace the SAID field value with '#' * fieldLength (the dummy)
 * 4. Serialize the structure (canonical JSON, CBOR, or MGPK)
 * 5. Compute digest of serialized bytes, encode as CESR primitive = the SAID
 *
 * The SAID is then placed back into the field, making the structure self-referential.
 */

import { digest, type HashAlgo, DIGEST_CODES } from './hash.js';
import { CODE_TABLE, encodePrimitive, type CesrPrimitive } from './cesr-codec.js';

/**
 * Compute a SAID for a JSON structure.
 *
 * @param json - The parsed JSON object
 * @param field - The field name containing the SAID (typically 'd' or 'i')
 * @param code - CESR derivation code (default 'E' = Blake3-256)
 * @returns The computed SAID as a CESR-encoded string
 */
export function computeSaid(
  json: Record<string, unknown>,
  field: string,
  code: string = 'E',
): string {
  const codeEntry = CODE_TABLE[code];
  if (!codeEntry) throw new Error(`Unknown SAID code: ${code}`);
  const digestInfo = DIGEST_CODES[code];
  if (!digestInfo) throw new Error(`Code ${code} is not a digest code`);

  // Step 2: dummy string of the correct length
  const dummy = '#'.repeat(codeEntry.fs);

  // Step 3: replace field with dummy
  const dummied = { ...json, [field]: dummy };

  // Step 4: serialize (canonical JSON with keys in insertion order, no spaces)
  const serialized = new TextEncoder().encode(JSON.stringify(dummied));

  // Step 5: digest + CESR encode
  const raw = digest(serialized, digestInfo.algo);
  const primitive: CesrPrimitive = { entry: codeEntry, raw };
  return encodePrimitive(primitive);
}

/**
 * Verify that a SAID field in a JSON structure is correct.
 *
 * @param json - The parsed JSON object containing the SAID
 * @param field - The field name containing the SAID
 * @returns true if the SAID is valid
 */
export function verifySaid(
  json: Record<string, unknown>,
  field: string,
): boolean {
  const existingSaid = json[field];
  if (typeof existingSaid !== 'string' || existingSaid.length === 0) return false;

  // Determine code from the first character(s) of the SAID
  const code = inferCode(existingSaid);
  if (!code) return false;

  const computed = computeSaid(json, field, code);
  return computed === existingSaid;
}

/**
 * Compute SAIDs for a KERI event where both 'd' and 'i' fields are SAIDive.
 * For inception events, i == d (the prefix IS the SAID of the inception event).
 */
export function computeEventSaids(
  event: Record<string, unknown>,
  code: string = 'E',
): Record<string, unknown> {
  const codeEntry = CODE_TABLE[code];
  if (!codeEntry) throw new Error(`Unknown SAID code: ${code}`);

  const dummy = '#'.repeat(codeEntry.fs);
  const ilk = event['t'] as string;

  if (ilk === 'icp' || ilk === 'dip') {
    // For inception: d and i are both SAIDive and equal
    const dummied = { ...event, d: dummy, i: dummy };
    const serialized = new TextEncoder().encode(JSON.stringify(dummied));
    const digestInfo = DIGEST_CODES[code]!;
    const raw = digest(serialized, digestInfo.algo);
    const said = encodePrimitive({ entry: codeEntry, raw });
    return { ...event, d: said, i: said };
  } else {
    // For rot/ixn/drt: only d is SAIDive, i is the AID prefix
    const dummied = { ...event, d: dummy };
    const serialized = new TextEncoder().encode(JSON.stringify(dummied));
    const digestInfo = DIGEST_CODES[code]!;
    const raw = digest(serialized, digestInfo.algo);
    const said = encodePrimitive({ entry: codeEntry, raw });
    return { ...event, d: said };
  }
}

/** Infer the CESR code from a SAID string by checking known code prefixes. */
function inferCode(said: string): string | null {
  // Try 4-char, 2-char, then 1-char
  if (said.startsWith('1') && said.length >= 4) {
    const c4 = said.substring(0, 4);
    if (DIGEST_CODES[c4]) return c4;
  }
  if (said.startsWith('0') && said.length >= 2) {
    const c2 = said.substring(0, 2);
    if (DIGEST_CODES[c2]) return c2;
  }
  const c1 = said[0];
  if (DIGEST_CODES[c1]) return c1;
  return null;
}
