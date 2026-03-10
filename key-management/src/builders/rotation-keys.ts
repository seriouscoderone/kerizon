/**
 * RotationKeySetBuilder — configures key rotation for an existing identifier.
 *
 * Cross-ref: keeping.py:1121 (Manager.rotate)
 */
import { MtrDex } from "../cesr-helpers.js";
import type { Verfer, Diger } from "../cesr-helpers.js";
import type { KeyVault } from "../key-vault.js";
import { PrefixNotFoundError } from "../errors.js";

export class RotationKeySetBuilder {
  private _prefix: string | null = null;
  private _nextCount = 1;
  private _nextCodes: string[] | null = null;
  private _digestCode: string = MtrDex.Blake3_256;
  private _transferable = true;
  private _eraseStaleKeys = true;
  private _testMode = false;

  forIdentifier(prefix: string): this {
    this._prefix = prefix;
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

  eraseStaleKeys(erase: boolean): this {
    this._eraseStaleKeys = erase;
    return this;
  }

  testMode(testMode: boolean): this {
    this._testMode = testMode;
    return this;
  }

  build(vault: KeyVault): { verfers: Verfer[]; digers: Diger[] } {
    if (!this._prefix) {
      throw new PrefixNotFoundError("RotationKeySetBuilder: prefix not set");
    }

    return vault.rotateKeys({
      prefix: this._prefix,
      nextCodes: this._nextCodes,
      nextCount: this._nextCount,
      nextCode: MtrDex.Ed25519_Seed,
      digestCode: this._digestCode,
      transferable: this._transferable,
      testMode: this._testMode,
      eraseStaleKeys: this._eraseStaleKeys,
    });
  }
}
