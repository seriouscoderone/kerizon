/**
 * SecretEncryptor — encrypts secrets using X25519 sealed box.
 *
 * Cross-ref: signing.py:750 (Encrypter)
 */
import {
  MtrDex,
  matterEncode,
  matterDecode,
  makeEncryptedSecretFromRaw,
} from "../cesr-helpers.js";
import type { EncryptedSecret } from "../types.js";
import type { ICryptographicSuite } from "../ports/cryptographic-suite.js";
import { DerivationError } from "../errors.js";
import type { ISecretEncryptor } from "../ports/key-store.js";

export class SecretEncryptor implements ISecretEncryptor {
  /** 32-byte X25519 public key */
  readonly raw: Uint8Array;
  /** qb64 of the X25519 public key */
  readonly qb64: string;
  private readonly crypto: ICryptographicSuite;

  constructor(opts: {
    raw?: Uint8Array;
    verkey?: string;
    crypto: ICryptographicSuite;
  }) {
    this.crypto = opts.crypto;

    if (opts.verkey) {
      const code = opts.verkey[0];
      if (code !== MtrDex.Ed25519 && code !== MtrDex.Ed25519N) {
        throw new DerivationError(
          `SecretEncryptor requires Ed25519 or Ed25519N verkey, got code: ${code}`,
        );
      }
      const edPubKey = matterDecode(opts.verkey);
      this.raw = opts.crypto.edPublicToX25519(edPubKey);
    } else if (opts.raw) {
      this.raw = opts.raw.slice();
    } else {
      throw new DerivationError("SecretEncryptor requires raw or verkey");
    }

    this.qb64 = matterEncode(this.raw, MtrDex.X25519);
  }

  /**
   * Encrypt a primitive or raw bytes.
   *
   * When encrypting a primitive:
   * - Salt_128 → X25519_Cipher_Salt (encrypts the 24-char qb64 of the salt)
   * - Ed25519_Seed → X25519_Cipher_Seed (encrypts the 44-char qb64 of the seed)
   *
   * Cross-ref: signing.py:817 (Encrypter.encrypt)
   */
  encrypt(
    ser?: Uint8Array,
    prim?: { raw: Uint8Array; qb64: string; code: string },
    code?: string,
  ): EncryptedSecret {
    let plaintext: Uint8Array;
    let cipherCode: string;

    if (prim) {
      // Encrypt the qb64 representation of the primitive (as UTF-8 bytes)
      plaintext = new TextEncoder().encode(prim.qb64);
      if (prim.code === MtrDex.Salt_128) {
        cipherCode = MtrDex.X25519_Cipher_Salt;
      } else if (prim.code === MtrDex.Ed25519_Seed) {
        cipherCode = MtrDex.X25519_Cipher_Seed;
      } else if (code) {
        cipherCode = code;
      } else {
        throw new DerivationError(
          `Explicit cipher code required for primitive with code: ${prim.code}`,
        );
      }
    } else if (ser) {
      plaintext = ser;
      if (!code) {
        throw new DerivationError("Explicit cipher code required for ser encryption");
      }
      cipherCode = code;
    } else {
      throw new DerivationError("encrypt requires ser or prim");
    }

    const cipherRaw = this.crypto.sealedBoxEncrypt(plaintext, this.raw);
    return makeEncryptedSecretFromRaw(cipherRaw, cipherCode);
  }

  /**
   * Verify that a signing seed corresponds to the public key used to derive
   * this encryptor's X25519 key. Used for AEID authentication.
   *
   * Cross-ref: signing.py:801 (Encrypter.verifySeed)
   */
  verifySeed(seedQb64: string): boolean {
    try {
      const seedRaw = matterDecode(seedQb64);
      const { publicKey } = this.crypto.deriveEdKeyPair(seedRaw);
      const x25519Pub = this.crypto.edPublicToX25519(publicKey);
      if (x25519Pub.length !== this.raw.length) return false;
      return x25519Pub.every((b, i) => b === this.raw[i]);
    } catch {
      return false;
    }
  }
}
