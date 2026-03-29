/**
 * Verfer — public key primitive with Ed25519 signature verification.
 *
 * Extends Matter with a `verify(sig, ser)` method for Ed25519 codes (B, D).
 */

import { sha512 } from '@noble/hashes/sha2';
import * as ed from '@noble/ed25519';
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

import { Matter, type MatterArgs } from './matter.js';
import { MtrDex } from './code-table.js';

/** Set of codes that use Ed25519 verification. */
const ED25519_CODES = new Set<string>([MtrDex.Ed25519, MtrDex.Ed25519N]);

export class Verfer extends Matter {
  constructor(args: MatterArgs) {
    super(args);
  }

  /**
   * Verify a signature against serialized data.
   *
   * @param sig - 64-byte Ed25519 signature
   * @param ser - serialized data that was signed
   * @returns true if the signature is valid
   * @throws if this Verfer's code is not a supported verification algorithm
   */
  async verify(sig: Uint8Array, ser: Uint8Array): Promise<boolean> {
    if (ED25519_CODES.has(this.code)) {
      try {
        return ed.verify(sig, ser, this.raw);
      } catch {
        return false;
      }
    }
    throw new Error(`Unsupported verification code: "${this.code}"`);
  }
}
