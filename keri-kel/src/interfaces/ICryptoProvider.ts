/**
 * Abstraction for cryptographic operations.
 * Injected into Kever/Kevery constructors.
 * Production users can inject Blake3 or other algorithms.
 */
export interface ICryptoProvider {
  /**
   * Verify that a signature is valid for the given message and public key.
   * @param publicKeyBytes - Raw public key bytes
   * @param signatureBytes - Raw signature bytes
   * @param message - The signed message bytes
   * @returns true if the signature is valid
   */
  verifySignature(
    publicKeyBytes: Uint8Array,
    signatureBytes: Uint8Array,
    message: Uint8Array,
  ): Promise<boolean>;

  /**
   * Compute a digest of the given data.
   * @param data - The data to digest
   * @param algorithm - CESR digest code (e.g., "E" for Blake3-256, "I" for SHA-256)
   * @returns Raw digest bytes
   */
  digest(data: Uint8Array, algorithm?: string): Promise<Uint8Array>;
}
