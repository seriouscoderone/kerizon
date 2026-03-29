/**
 * Serder — Serialized Event Dictionary.
 *
 * Wraps a KERI Key Event Dictionary (KED) with:
 *   - Automatic version string generation with correct size
 *   - Automatic SAID computation (d field, and i field for inception)
 *   - Raw canonical JSON serialization
 *
 * The SAID depends on the serialized size, and the serialized size depends
 * on the SAID (circular). The algorithm iterates:
 *   1. Build KED with version string (size=0) and placeholder d/i
 *   2. Compute SAID with that version string
 *   3. Update version string with actual size
 *   4. Recompute SAID with correct version string
 *   5. Repeat until stable (fixed 3 passes)
 */

import { Saider } from '../primitives/saider.js';
import { MtrDex } from '../primitives/code-table.js';
import { makeVersionString, parseVersionString } from './version-string.js';

/** Event types where d and i share the same SAID. */
const INCEPTION_TYPES = new Set(['icp', 'dip']);

const DEFAULT_PROTOCOL = 'KERI';
const DEFAULT_MAJOR = 1;
const DEFAULT_MINOR = 0;
const DEFAULT_KIND = 'JSON';

export class Serder {
  readonly ked: Record<string, unknown>;
  readonly raw: Uint8Array;
  readonly said: string;

  private constructor(ked: Record<string, unknown>, raw: Uint8Array) {
    this.ked = ked;
    this.raw = raw;
    this.said = ked['d'] as string;
  }

  /**
   * Build a Serder from a KED template.
   *
   * Fields v, d (and i for inception) are computed automatically.
   * Any existing v/d/i values are replaced.
   *
   * @param fields  - the Key Event Dictionary template
   * @param code    - digest algorithm code (default: Blake3-256 / 'E')
   */
  static fromKed(
    fields: Record<string, unknown>,
    code: string = MtrDex.Blake3_256,
  ): Serder {
    // Work with a shallow copy
    let ked = { ...fields };

    // Run 3 iterations to converge on a stable SAID + size
    for (let i = 0; i < 3; i++) {
      // Set version string with current best-guess size (0 on first pass)
      const currentSize = i === 0 ? 0 : new TextEncoder().encode(JSON.stringify(ked)).length;
      ked['v'] = makeVersionString({
        protocol: DEFAULT_PROTOCOL,
        major: DEFAULT_MAJOR,
        minor: DEFAULT_MINOR,
        kind: DEFAULT_KIND,
        size: currentSize,
      });

      // Compute SAID (this replaces d, and i for inception types)
      ked = Saider.saidify(ked, 'd', code) as Record<string, unknown>;
    }

    // Final size update: the SAID is now stable, just fix the size
    const serialized = JSON.stringify(ked);
    const raw = new TextEncoder().encode(serialized);
    const vs = parseVersionString(ked['v'] as string);
    if (vs.size !== raw.length) {
      ked['v'] = makeVersionString({
        ...vs,
        size: raw.length,
      });
      // One more saidify with the final version string
      ked = Saider.saidify(ked, 'd', code) as Record<string, unknown>;
    }

    // Final serialization
    const finalSerialized = JSON.stringify(ked);
    const finalRaw = new TextEncoder().encode(finalSerialized);

    // Sanity: verify the encoded size matches
    const finalVs = parseVersionString(ked['v'] as string);
    if (finalVs.size !== finalRaw.length) {
      // One last size fix + saidify (should not normally happen)
      ked['v'] = makeVersionString({ ...finalVs, size: finalRaw.length });
      ked = Saider.saidify(ked, 'd', code) as Record<string, unknown>;
      const lastRaw = new TextEncoder().encode(JSON.stringify(ked));
      return new Serder(ked, lastRaw);
    }

    return new Serder(ked, finalRaw);
  }

  /**
   * Reconstruct a Serder from raw JSON bytes.
   */
  static fromRaw(raw: Uint8Array): Serder {
    const text = new TextDecoder().decode(raw);
    const ked = JSON.parse(text) as Record<string, unknown>;
    return new Serder(ked, raw);
  }

  /**
   * Verify that the SAID in ked.d is correct for the current serialization.
   */
  verifySaid(): boolean {
    return Saider.verify(this.ked, 'd');
  }

  /** Event type (ilk), e.g. 'icp', 'rot', 'ixn'. */
  get ilk(): string {
    return this.ked['t'] as string;
  }

  /** AID prefix (the i field). */
  get pre(): string {
    return this.ked['i'] as string;
  }

  /** Sequence number, parsed from hex string. */
  get sn(): number {
    const s = this.ked['s'] as string;
    return parseInt(s, 16);
  }
}
