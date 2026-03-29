/**
 * Signer — private key (seed) primitive with Ed25519 signing.
 *
 * Extends Matter. Holds a 32-byte Ed25519 seed (code 'A') and provides
 * key generation, signing, and public key derivation.
 */

import { sha512 } from '@noble/hashes/sha2';
import * as ed from '@noble/ed25519';
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

import { Matter, type MatterArgs } from './matter.js';
import { MtrDex } from './code-table.js';
import { Verfer } from './verfer.js';

export class Signer extends Matter {
  private _verfer: Verfer | null = null;

  constructor(args: MatterArgs) {
    super(args);
  }

  /**
   * Generate a random Ed25519 keypair.
   *
   * @param code - seed code (default: 'A' / Ed25519_Seed)
   * @returns a new Signer with a random 32-byte seed
   */
  static async generate(code: string = MtrDex.Ed25519_Seed): Promise<Signer> {
    const raw = ed.utils.randomPrivateKey();
    return new Signer({ code, raw });
  }

  /**
   * The corresponding Ed25519 public key, lazily derived from the seed.
   */
  get verfer(): Verfer {
    if (this._verfer === null) {
      const pubKey = ed.getPublicKey(this.raw);
      this._verfer = new Verfer({ code: MtrDex.Ed25519, raw: pubKey });
    }
    return this._verfer;
  }

  /**
   * Sign serialized data with this Ed25519 private key.
   *
   * @param ser - data to sign
   * @returns 64-byte Ed25519 signature
   */
  async sign(ser: Uint8Array): Promise<Uint8Array> {
    return ed.sign(ser, this.raw);
  }
}
