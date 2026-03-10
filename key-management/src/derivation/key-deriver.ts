/**
 * KeyDeriver — deterministic key derivation from a 128-bit salt via Argon2ID.
 *
 * Cross-ref: signing.py:329 (Salter)
 */
import { MtrDex, matterEncode, matterDecode } from "../cesr-helpers.js";
import { SecurityTier, SecurityTierParams } from "../types.js";
import { DerivationError } from "../errors.js";
import type { ICryptographicSuite } from "../ports/cryptographic-suite.js";
import { makeSigningKey, type SigningKey } from "../signing-key.js";

/** Minimal test mode parameters. */
const TEST_MODE_PARAMS = { ops: 1, mem: 8 } as const;

export class KeyDeriver {
  /** 16-byte raw salt */
  readonly raw: Uint8Array;
  /** qb64 of the salt (code "0A", 24 chars) */
  readonly qb64: string;
  readonly tier: SecurityTier;
  private readonly crypto: ICryptographicSuite;

  constructor(opts: {
    raw?: Uint8Array;
    qb64?: string;
    tier?: SecurityTier;
    crypto: ICryptographicSuite;
  }) {
    this.crypto = opts.crypto;
    this.tier = opts.tier ?? SecurityTier.LOW;

    if (opts.raw) {
      if (opts.raw.length !== 16) {
        throw new DerivationError(`Salt must be 16 bytes, got ${opts.raw.length}`);
      }
      this.raw = opts.raw.slice();
    } else if (opts.qb64) {
      const decoded = matterDecode(opts.qb64);
      if (decoded.length !== 16) {
        throw new DerivationError(`Decoded salt must be 16 bytes, got ${decoded.length}`);
      }
      this.raw = decoded;
    } else {
      // Generate fresh random 16-byte salt
      this.raw = opts.crypto.generateRandom(16);
    }

    this.qb64 = matterEncode(this.raw, MtrDex.Salt_128);
  }

  /**
   * Stretch the salt to `size` bytes of key material.
   * The `path` uniquely differentiates each key in the sequence.
   *
   * Cross-ref: signing.py:411 (Salter.stretch)
   */
  stretch(
    size: number,
    path: string,
    tier?: SecurityTier,
    testMode = false,
  ): Uint8Array {
    const t = tier ?? this.tier;
    const tierParams = SecurityTierParams[t];
    if (!tierParams) {
      throw new DerivationError(`Unknown security tier: ${t}`);
    }
    const { ops, mem } = testMode ? TEST_MODE_PARAMS : tierParams;
    const pathBytes = new TextEncoder().encode(path);
    return this.crypto.stretchKey(pathBytes, this.raw, size, ops, mem);
  }

  /**
   * Derive a SigningKey from this salt + path.
   *
   * Cross-ref: signing.py:450 (Salter.signer)
   */
  signer(
    code: string,
    transferable: boolean,
    path: string,
    tier?: SecurityTier,
    testMode = false,
  ): SigningKey {
    // For Ed25519_Seed ("A"), raw size is 32 bytes
    const rawSize = 32;
    const raw = this.stretch(rawSize, path, tier, testMode);
    return makeSigningKey(raw, transferable);
  }

  /**
   * Derive `count` signers with sequential paths.
   *
   * Path for signer at offset i: `"{path}{(start+i).toString(16)}"`
   *
   * Cross-ref: signing.py:471 (Salter.signers)
   */
  signers(
    count: number,
    start: number,
    path: string,
    code: string,
    transferable: boolean,
    tier?: SecurityTier,
    testMode = false,
  ): SigningKey[] {
    const result: SigningKey[] = [];
    for (let i = 0; i < count; i++) {
      const p = `${path}${(start + i).toString(16)}`;
      result.push(this.signer(code, transferable, p, tier, testMode));
    }
    return result;
  }
}
