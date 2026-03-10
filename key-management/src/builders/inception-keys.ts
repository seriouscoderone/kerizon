/**
 * InceptionKeySetBuilder — configures initial key pairs for a new identifier.
 *
 * Cross-ref: keeping.py:928 (Manager.incept)
 */
import { KeyAlgorithm, SecurityTier } from "../types.js";
import { MtrDex } from "../cesr-helpers.js";
import type { Verfer, Diger } from "../cesr-helpers.js";
import type { KeyVault } from "../key-vault.js";
import { DerivationError } from "../errors.js";

export class InceptionKeySetBuilder {
  private _algorithm: KeyAlgorithm | null = null;
  private _salt: string | null = null;
  private _stem: string | null = null;
  private _tier: SecurityTier | null = null;
  private _rooted = true;
  private _currentCount = 1;
  private _currentCodes: string[] | null = null;
  private _nextCount = 1;
  private _nextCodes: string[] | null = null;
  private _digestCode: string = MtrDex.Blake3_256;
  private _transferable = true;
  private _testMode = false;

  algorithm(algo: KeyAlgorithm): this {
    this._algorithm = algo;
    return this;
  }

  salt(salt: string): this {
    this._salt = salt;
    return this;
  }

  stem(stem: string): this {
    this._stem = stem;
    return this;
  }

  tier(tier: SecurityTier): this {
    this._tier = tier;
    return this;
  }

  rooted(rooted: boolean): this {
    this._rooted = rooted;
    return this;
  }

  currentCount(count: number): this {
    this._currentCount = count;
    return this;
  }

  currentCodes(codes: string[]): this {
    this._currentCodes = codes;
    return this;
  }

  nextCount(count: number): this {
    this._nextCount = count;
    return this;
  }

  nextCodes(codes: string[]): this {
    this._nextCodes = codes;
    return this;
  }

  digestCode(code: string): this {
    this._digestCode = code;
    return this;
  }

  transferable(transferable: boolean): this {
    this._transferable = transferable;
    return this;
  }

  testMode(testMode: boolean): this {
    this._testMode = testMode;
    return this;
  }

  build(vault: KeyVault): { verfers: Verfer[]; digers: Diger[] } {
    const resolvedCount = this._currentCodes
      ? this._currentCodes.length
      : this._currentCount;
    if (resolvedCount <= 0) {
      throw new DerivationError("InceptionKeySetBuilder: currentCount must be > 0");
    }
    const resolvedNextCount = this._nextCodes
      ? this._nextCodes.length
      : this._nextCount;
    if (resolvedNextCount < 0) {
      throw new DerivationError("InceptionKeySetBuilder: nextCount must be >= 0");
    }

    return vault.inceptKeys({
      currentCodes: this._currentCodes,
      currentCount: this._currentCount,
      currentCode: MtrDex.Ed25519_Seed,
      nextCodes: this._nextCodes,
      nextCount: this._nextCount,
      nextCode: MtrDex.Ed25519_Seed,
      digestCode: this._digestCode,
      algorithm: this._algorithm,
      salt: this._salt,
      stem: this._stem,
      tier: this._tier,
      rooted: this._rooted,
      transferable: this._transferable,
      testMode: this._testMode,
    });
  }
}
