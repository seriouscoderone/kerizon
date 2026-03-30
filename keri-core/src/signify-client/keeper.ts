/**
 * SimpleKeeper — basic in-memory keeper for testing.
 * Production keepers would use secure storage (keychain, HSM).
 */

import { Signer, Diger } from '@kerizon/cesr';
import type { Keeper, SecurityTier } from './types.js';

export class SimpleKeeper implements Keeper {
  readonly tier: SecurityTier;
  readonly prefix: string;
  private signers: Signer[];
  private nextSigners: Signer[];

  private constructor(
    tier: SecurityTier,
    prefix: string,
    signers: Signer[],
    nextSigners: Signer[],
  ) {
    this.tier = tier;
    this.prefix = prefix;
    this.signers = signers;
    this.nextSigners = nextSigners;
  }

  /**
   * Create a new SimpleKeeper with randomly generated Ed25519 keys.
   *
   * @param tier - security tier (default: 'low')
   */
  static async create(tier: SecurityTier = 'low'): Promise<SimpleKeeper> {
    const signer = await Signer.generate();
    const nextSigner = await Signer.generate();
    const prefix = signer.verfer.qb64;
    return new SimpleKeeper(tier, prefix, [signer], [nextSigner]);
  }

  /** Sign data with the current signing keys. */
  async sign(data: Uint8Array): Promise<Uint8Array[]> {
    const sigs: Uint8Array[] = [];
    for (const signer of this.signers) {
      sigs.push(await signer.sign(data));
    }
    return sigs;
  }

  /** Rotate to next pre-committed keys and generate new next keys. */
  async rotate(): Promise<void> {
    this.signers = this.nextSigners;
    this.nextSigners = [await Signer.generate()];
  }

  /** Derive a key from a path. Returns a deterministic-length byte array. */
  async deriveKey(path: string): Promise<Uint8Array> {
    // Simple derivation: hash the path string combined with the current seed
    const encoder = new TextEncoder();
    const pathBytes = encoder.encode(path);
    const diger = Diger.digest(pathBytes);
    return diger.raw;
  }

  /** Get current public keys as qb64. */
  get currentKeys(): string[] {
    return this.signers.map((s) => s.verfer.qb64);
  }

  /** Get next key digests as qb64. */
  get nextKeyDigests(): string[] {
    return this.nextSigners.map((s) => {
      const diger = Diger.digest(s.verfer.raw);
      return diger.qb64;
    });
  }
}
