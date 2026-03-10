/**
 * CryptographicSuite port interface — abstracts all cryptographic primitives.
 */
export interface ICryptographicSuite {
  /**
   * Derives an Ed25519 key pair from a 32-byte seed.
   * Returns { publicKey: 32 bytes, signingKey: 32 bytes seed }
   */
  deriveEdKeyPair(seed: Uint8Array): { publicKey: Uint8Array; signingKey: Uint8Array };

  /**
   * Derives an ECDSA key pair from a seed on a named curve.
   * @param curve - "secp256r1" (P-256) or "secp256k1"
   */
  deriveEcKeyPair(
    seed: Uint8Array,
    curve: string,
  ): { publicKey: Uint8Array; signingKey: Uint8Array };

  /**
   * Ed25519 detached signature.
   */
  edSign(message: Uint8Array, signingKey: Uint8Array): Uint8Array;

  /**
   * ECDSA detached signature (r || s, 64 bytes).
   */
  ecSign(message: Uint8Array, seed: Uint8Array, curve: string): Uint8Array;

  /**
   * Argon2ID key stretching.
   * @param password - Input password bytes
   * @param salt - Random salt bytes
   * @param outLength - Number of output bytes
   * @param opsLimit - Argon2ID time cost (iterations)
   * @param memLimit - Argon2ID memory cost in KiB
   */
  stretchKey(
    password: Uint8Array,
    salt: Uint8Array,
    outLength: number,
    opsLimit: number,
    memLimit: number,
  ): Uint8Array;

  /**
   * Cryptographically secure random bytes.
   */
  generateRandom(size: number): Uint8Array;

  /**
   * X25519 sealed box encryption.
   */
  sealedBoxEncrypt(plaintext: Uint8Array, publicKey: Uint8Array): Uint8Array;

  /**
   * X25519 sealed box decryption.
   * Returns null if decryption fails.
   */
  sealedBoxDecrypt(
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    privateKey: Uint8Array,
  ): Uint8Array | null;

  /**
   * Converts an Ed25519 public key to an X25519 public key.
   */
  edPublicToX25519(edPublicKey: Uint8Array): Uint8Array;

  /**
   * Converts an Ed25519 signing key (seed + verkey, 64 bytes) to X25519 private key.
   */
  edPrivateToX25519(edSigningKey: Uint8Array): Uint8Array;

  /**
   * Computes X25519 public key from private key (scalar base multiplication).
   */
  x25519Base(privateKey: Uint8Array): Uint8Array;
}
