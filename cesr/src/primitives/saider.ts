/**
 * Saider — SAID (Self-Addressing Identifier) computation and verification.
 *
 * Implements the SAID protocol: replace the designated label field with a
 * placeholder of the correct length, serialize to JSON, digest, and encode
 * the result as a CESR primitive (default: Blake3-256 / code 'E').
 *
 * For inception events (t=='icp' or t=='dip'), both 'd' and 'i' fields
 * receive the same SAID value.
 */

import { Diger } from './diger.js';
import { MtrDex, MtrSizage } from './code-table.js';

/** Event types where d and i must share the same SAID. */
const INCEPTION_TYPES = new Set(['icp', 'dip']);

export class Saider {
  /**
   * Compute the SAID for `fields` and return a new object with the SAID
   * populated in the label field.
   *
   * @param fields - the record to saidify
   * @param label - which field holds the SAID (default: 'd')
   * @param code - digest algorithm code (default: 'E' / Blake3-256)
   * @returns a shallow copy of fields with the SAID inserted
   */
  static saidify(
    fields: Record<string, unknown>,
    label: string = 'd',
    code: string = MtrDex.Blake3_256,
  ): Record<string, unknown> {
    const sizage = MtrSizage[code];
    if (!sizage) {
      throw new Error(`Unknown digest code for SAID: "${code}"`);
    }

    // Build placeholder: '#' repeated to the full qb64 size
    const placeholder = '#'.repeat(sizage.fs);

    // Determine if this is an inception event
    const eventType = fields['t'] as string | undefined;
    const isInception = eventType !== undefined && INCEPTION_TYPES.has(eventType);

    // Create the template with placeholder(s)
    const template = { ...fields, [label]: placeholder };
    if (isInception && 'i' in fields) {
      template['i'] = placeholder;
    }

    // Serialize to JSON (deterministic: no extra whitespace)
    const ser = new TextEncoder().encode(JSON.stringify(template));

    // Digest
    const diger = Diger.digest(ser, code);
    const said = diger.qb64;

    // Build result
    const result = { ...fields, [label]: said };
    if (isInception && 'i' in fields) {
      result['i'] = said;
    }

    return result;
  }

  /**
   * Verify that the SAID in `fields[label]` is correct.
   *
   * Re-computes the SAID from scratch and compares it to the stored value.
   *
   * @param fields - the record to verify
   * @param label - which field holds the SAID (default: 'd')
   * @returns true if the recomputed SAID matches
   */
  static verify(
    fields: Record<string, unknown>,
    label: string = 'd',
  ): boolean {
    const currentSaid = fields[label];
    if (typeof currentSaid !== 'string' || currentSaid.length === 0) {
      return false;
    }

    // Infer the code from the first character(s) of the existing SAID
    const code = Saider._inferCode(currentSaid);

    // Recompute
    const recomputed = Saider.saidify(fields, label, code);

    return recomputed[label] === currentSaid;
  }

  /**
   * Infer the Matter code from a qb64 string prefix.
   */
  private static _inferCode(qb64: string): string {
    const HS4_CHARS = new Set(['1', '2', '3', '7', '8', '9']);
    const HS2_CHARS = new Set(['0', '4', '5', '6']);
    const first = qb64[0];

    if (HS4_CHARS.has(first) && qb64.length >= 4) {
      const c4 = qb64.substring(0, 4);
      if (MtrSizage[c4]) return c4;
    }
    if (HS2_CHARS.has(first) && qb64.length >= 2) {
      const c2 = qb64.substring(0, 2);
      if (MtrSizage[c2]) return c2;
    }
    if (MtrSizage[first]) return first;

    return MtrDex.Blake3_256; // fallback
  }
}
