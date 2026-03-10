import type { ICryptoProvider } from "../interfaces/ICryptoProvider.js";

/**
 * Default crypto provider using Web Crypto API.
 * Supports Ed25519 signature verification and SHA-256 digests.
 * Production deployments should use Blake3 for digests.
 */
export class DefaultCryptoProvider implements ICryptoProvider {
  async verifySignature(
    publicKeyBytes: Uint8Array,
    signatureBytes: Uint8Array,
    message: Uint8Array,
  ): Promise<boolean> {
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes.slice(),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        "Ed25519",
        key,
        signatureBytes.slice(),
        message.slice(),
      );
    } catch {
      return false;
    }
  }

  async digest(data: Uint8Array, algorithm?: string): Promise<Uint8Array> {
    // Default to SHA-256. Production should use Blake3 (code "E").
    const hash = await crypto.subtle.digest("SHA-256", data.slice());
    return new Uint8Array(hash);
  }
}
