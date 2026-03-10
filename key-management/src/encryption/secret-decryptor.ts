/**
 * SecretDecryptor — decrypts secrets using X25519 sealed box.
 *
 * Cross-ref: signing.py:885 (Decrypter)
 */
import {
  MtrDex,
  matterEncode,
  matterDecode,
  encryptedSecretFromQb64,
} from "../cesr-helpers.js";
import type { EncryptedSecret } from "../types.js";
import type { ICryptographicSuite } from "../ports/cryptographic-suite.js";
import { DerivationError, DecryptionError } from "../errors.js";
import type { ISecretDecryptor } from "../ports/key-store.js";
import { makeSigningKey, type SigningKey } from "../signing-key.js";
import { KeyDeriver } from "../derivation/key-deriver.js";
import { SecurityTier } from "../types.js";

export class SecretDecryptor implements ISecretDecryptor {
  /** 32-byte X25519 private key */
  readonly raw: Uint8Array;
  /** qb64 of the X25519 private key */
  readonly qb64: string;
  private readonly crypto: ICryptographicSuite;

  constructor(opts: {
    seed?: string;
    raw?: Uint8Array;
    crypto: ICryptographicSuite;
  }) {
    this.crypto = opts.crypto;

    if (opts.seed) {
      const seedCode = opts.seed[0];
      if (seedCode !== MtrDex.Ed25519_Seed) {
        throw new DerivationError(
          `SecretDecryptor requires Ed25519_Seed code "A", got: ${seedCode}`,
        );
      }
      const seedRaw = matterDecode(opts.seed);
      // Derive public key from seed
      const { publicKey } = opts.crypto.deriveEdKeyPair(seedRaw);
      // Build 64-byte signing key = seed || pubkey
      const sigKey = new Uint8Array(64);
      sigKey.set(seedRaw);
      sigKey.set(publicKey, 32);
      // Convert to X25519 private key
      this.raw = opts.crypto.edPrivateToX25519(sigKey);
    } else if (opts.raw) {
      this.raw = opts.raw.slice();
    } else {
      throw new DerivationError("SecretDecryptor requires seed or raw");
    }

    this.qb64 = matterEncode(this.raw, MtrDex.X25519_Private);
  }

  /**
   * Decrypt cipher text, returning a typed result based on cipher code.
   *
   * - X25519_Cipher_Salt → KeyDeriver
   * - X25519_Cipher_Seed → SigningKey
   * - bare=true → raw bytes
   *
   * Cross-ref: signing.py:949 (Decrypter.decrypt)
   */
  decrypt(
    cipher?: EncryptedSecret,
    qb64?: string,
    klas?: "salt" | "seed",
    transferable = true,
    bare = false,
  ): SigningKey | KeyDeriver | Uint8Array {
    // Resolve cipher
    const ciph =
      cipher ??
      (qb64 ? encryptedSecretFromQb64(qb64) : undefined);
    if (!ciph) {
      throw new DecryptionError("No cipher provided to decrypt");
    }

    // Compute X25519 public key from private key
    const x25519Pub = this.crypto.x25519Base(this.raw);

    // Decrypt
    const plaintext = this.crypto.sealedBoxDecrypt(ciph.raw, x25519Pub, this.raw);
    if (!plaintext || plaintext.length === 0) {
      throw new DecryptionError("Sealed box decryption failed");
    }

    if (bare) {
      return plaintext;
    }

    // Decode plaintext as UTF-8 qb64 string
    const plaintextStr = new TextDecoder().decode(plaintext);

    // Determine type from cipher code or explicit klas
    const effectiveKlas: "salt" | "seed" =
      klas ?? (ciph.code === MtrDex.X25519_Cipher_Salt ? "salt" : "seed");

    if (effectiveKlas === "salt") {
      return new KeyDeriver({ qb64: plaintextStr, crypto: this.crypto });
    } else {
      const seedRaw = matterDecode(plaintextStr);
      return makeSigningKey(seedRaw, transferable);
    }
  }
}
