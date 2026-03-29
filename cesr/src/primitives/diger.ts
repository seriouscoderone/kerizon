/**
 * Diger — digest primitive with multiple hash algorithm support.
 *
 * Extends Matter with static `digest()` and instance `compare()` methods.
 * Supported algorithms: Blake3-256 (E), Blake2b-256 (F), Blake2s-256 (G),
 * SHA3-256 (H), SHA2-256 (I).
 */

import { blake3 } from '@noble/hashes/blake3';
import { blake2b, blake2s } from '@noble/hashes/blake2';
import { sha3_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha2';

import { Matter, type MatterArgs } from './matter.js';
import { MtrDex } from './code-table.js';

/** Map from digest code to hash function (all produce 32 bytes). */
const DIGEST_FNS: Record<string, (data: Uint8Array) => Uint8Array> = {
  [MtrDex.Blake3_256]: (data) => blake3(data),
  [MtrDex.Blake2b_256]: (data) => blake2b(data, { dkLen: 32 }),
  [MtrDex.Blake2s_256]: (data) => blake2s(data, { dkLen: 32 }),
  [MtrDex.SHA3_256]: (data) => sha3_256(data),
  [MtrDex.SHA2_256]: (data) => sha256(data),
};

export class Diger extends Matter {
  constructor(args: MatterArgs) {
    super(args);
  }

  /**
   * Compute a digest of data with the given algorithm code.
   *
   * @param data - bytes to digest
   * @param code - digest algorithm code (default: 'E' / Blake3-256)
   * @returns a new Diger holding the digest
   */
  static digest(data: Uint8Array, code: string = MtrDex.Blake3_256): Diger {
    const hashFn = DIGEST_FNS[code];
    if (!hashFn) {
      throw new Error(`Unsupported digest code: "${code}"`);
    }
    const raw = hashFn(data);
    return new Diger({ code, raw });
  }

  /**
   * Compare: does the digest of data match this Diger's value?
   *
   * @param data - bytes to digest and compare
   * @returns true if the computed digest matches this Diger's raw bytes
   */
  compare(data: Uint8Array): boolean {
    const hashFn = DIGEST_FNS[this.code];
    if (!hashFn) {
      return false;
    }
    const computed = hashFn(data);
    if (computed.length !== this.raw.length) return false;
    // Constant-time-ish comparison
    let diff = 0;
    for (let i = 0; i < computed.length; i++) {
      diff |= computed[i] ^ this.raw[i];
    }
    return diff === 0;
  }
}
