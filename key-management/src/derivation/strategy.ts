/**
 * Key generation strategies.
 *
 * Cross-ref:
 *   keeping.py:357 (Creator)
 *   keeping.py:408 (RandyCreator)
 *   keeping.py:452 (SaltyCreator)
 *   keeping.py:536 (Creatory)
 */
import { KeyAlgorithm, SecurityTier } from "../types.js";
import { DerivationError } from "../errors.js";
import type { ICryptographicSuite } from "../ports/cryptographic-suite.js";
import { makeSigningKey, type SigningKey } from "../signing-key.js";
import { KeyDeriver } from "./key-deriver.js";

/** Abstract interface for key pair creation algorithms. */
export interface IKeyGenerationStrategy {
  create(
    codes: string[] | null,
    count: number,
    code: string,
    pidx: number,
    ridx: number,
    kidx: number,
    transferable: boolean,
    testMode: boolean,
  ): SigningKey[];

  readonly salt: string;
  readonly stem: string;
  readonly tier: string;
}

/**
 * RandomKeyGenerator — each key pair uses fresh random entropy.
 *
 * Cross-ref: keeping.py:408 (RandyCreator)
 */
export class RandomKeyGenerator implements IKeyGenerationStrategy {
  readonly salt = "";
  readonly stem = "";
  readonly tier = "";
  private readonly crypto: ICryptographicSuite;

  constructor(crypto: ICryptographicSuite) {
    this.crypto = crypto;
  }

  create(
    codes: string[] | null,
    count: number,
    code: string,
    _pidx: number,
    _ridx: number,
    _kidx: number,
    transferable: boolean,
    _testMode: boolean,
  ): SigningKey[] {
    const resolvedCodes = codes ?? Array(count).fill(code);
    return resolvedCodes.map(() => {
      const raw = this.crypto.generateRandom(32);
      return makeSigningKey(raw, transferable);
    });
  }
}

/**
 * DeterministicKeyGenerator — key pairs derived deterministically from salt + path.
 *
 * Cross-ref: keeping.py:452 (SaltyCreator)
 */
export class DeterministicKeyGenerator implements IKeyGenerationStrategy {
  readonly salt: string;
  readonly stem: string;
  readonly tier: string;
  private readonly deriver: KeyDeriver;

  constructor(
    salt: string | null,
    stem: string | null,
    tier: SecurityTier | null,
    crypto: ICryptographicSuite,
  ) {
    const resolvedTier = tier ?? SecurityTier.LOW;
    if (salt) {
      this.deriver = new KeyDeriver({ qb64: salt, tier: resolvedTier, crypto });
    } else {
      this.deriver = new KeyDeriver({ tier: resolvedTier, crypto });
    }
    this.salt = this.deriver.qb64;
    this.stem = stem ?? "";
    this.tier = resolvedTier;
  }

  create(
    codes: string[] | null,
    count: number,
    code: string,
    pidx: number,
    ridx: number,
    kidx: number,
    transferable: boolean,
    testMode: boolean,
  ): SigningKey[] {
    const resolvedCodes = codes ?? Array(count).fill(code);
    // Resolve stem: if empty, use pidx as hex
    const stem = this.stem || pidx.toString(16);

    return resolvedCodes.map((_, i) => {
      // Path: "{stem}{ridx:x}{kidx+i:x}"
      const path = `${stem}${ridx.toString(16)}${(kidx + i).toString(16)}`;
      return this.deriver.signer(
        code,
        transferable,
        path,
        this.tier as SecurityTier,
        testMode,
      );
    });
  }
}

/**
 * KeyGeneratorFactory — creates the appropriate strategy based on algorithm.
 *
 * Cross-ref: keeping.py:536 (Creatory)
 */
export class KeyGeneratorFactory {
  constructor(private readonly algorithm: KeyAlgorithm) {}

  make(
    salt: string | null,
    stem: string | null,
    tier: SecurityTier | null,
    crypto: ICryptographicSuite,
  ): IKeyGenerationStrategy {
    switch (this.algorithm) {
      case KeyAlgorithm.RANDOM:
        return new RandomKeyGenerator(crypto);
      case KeyAlgorithm.DETERMINISTIC:
        return new DeterministicKeyGenerator(salt, stem, tier, crypto);
      default:
        throw new DerivationError(
          `KeyGeneratorFactory: unsupported algorithm: ${this.algorithm}`,
        );
    }
  }
}
