/**
 * InMemoryKeyStore — in-memory implementation of IKeyStore for testing.
 */
import { KeyStoreClosedError } from "../errors.js";
import type {
  IKeyStore,
  ISecretEncryptor,
  ISecretDecryptor,
  MemberEntry,
} from "../ports/key-store.js";
import type { SigningKey } from "../signing-key.js";
import { makeSigningKey } from "../signing-key.js";
import {
  type EncryptedSecret,
  type DerivationParameters,
  type KeySituation,
  type PublicKeySet,
} from "../types.js";
import { encryptedSecretFromQb64, matterDecode } from "../cesr-helpers.js";

/**
 * Stored private key entry: either plaintext qb64 seed or encrypted cipher qb64.
 */
interface StoredKey {
  /** qb64 of the seed (if unencrypted) */
  seedQb64?: string;
  /** qb64 of the encrypted cipher (if encrypted) */
  cipherQb64?: string;
  /** Whether key is stored encrypted */
  encrypted: boolean;
  /** Whether key was transferable (needed for reconstruction) */
  transferable?: boolean;
}

export class InMemoryKeyStore implements IKeyStore {
  private _isOpen = false;
  private globals = new Map<string, string>();
  private privateKeys = new Map<string, StoredKey>();
  private nextKeyCiphers = new Map<string, EncryptedSecret>();
  private prefixMappings = new Map<string, string>();
  private derivationParams = new Map<string, DerivationParameters>();
  private keySituations = new Map<string, KeySituation>();
  private publicKeySets = new Map<string, PublicKeySet>();
  private signingMembersMap = new Map<string, MemberEntry[]>();
  private rotatingMembersMap = new Map<string, MemberEntry[]>();

  open(): void {
    this._isOpen = true;
  }

  close(): void {
    this._isOpen = false;
  }

  isOpened(): boolean {
    return this._isOpen;
  }

  private checkOpen(): void {
    if (!this._isOpen) throw new KeyStoreClosedError();
  }

  // ── Globals ──────────────────────────────────────────────────────────

  getGlobal(key: string): string | null {
    this.checkOpen();
    return this.globals.get(key) ?? null;
  }

  putGlobal(key: string, value: string): void {
    this.checkOpen();
    this.globals.set(key, value);
  }

  pinGlobal(key: string, value: string): void {
    this.checkOpen();
    this.globals.set(key, value);
  }

  // ── Private Keys ─────────────────────────────────────────────────────

  putPrivateKey(
    publicKey: string,
    signer: SigningKey,
    encrypter: ISecretEncryptor | null,
  ): boolean {
    this.checkOpen();
    if (this.privateKeys.has(publicKey)) return false;
    this._storeKey(publicKey, signer, encrypter);
    return true;
  }

  private _storeKey(
    publicKey: string,
    signer: SigningKey,
    encrypter: ISecretEncryptor | null,
  ): void {
    if (encrypter) {
      const cipher = encrypter.encrypt(undefined, {
        raw: signer.raw,
        qb64: signer.qb64,
        code: signer.code,
      });
      this.privateKeys.set(publicKey, {
        cipherQb64: cipher.qb64,
        encrypted: true,
        transferable: signer.transferable,
      });
    } else {
      this.privateKeys.set(publicKey, {
        seedQb64: signer.qb64,
        encrypted: false,
        transferable: signer.transferable,
      });
    }
  }

  getPrivateKey(
    publicKey: string,
    decrypter: ISecretDecryptor | null,
  ): SigningKey | null {
    this.checkOpen();
    const stored = this.privateKeys.get(publicKey);
    if (!stored) return null;

    if (stored.encrypted) {
      if (!decrypter) return null;
      const cipher = encryptedSecretFromQb64(stored.cipherQb64!);
      const result = decrypter.decrypt(cipher, undefined, "seed", stored.transferable ?? true, false);
      return result as SigningKey;
    } else {
      const raw = matterDecode(stored.seedQb64!);
      return makeSigningKey(raw, stored.transferable ?? true);
    }
  }

  removePrivateKey(publicKey: string): boolean {
    this.checkOpen();
    return this.privateKeys.delete(publicKey);
  }

  pinPrivateKey(
    publicKey: string,
    signer: SigningKey,
    encrypter: ISecretEncryptor | null,
  ): boolean {
    this.checkOpen();
    this._storeKey(publicKey, signer, encrypter);
    return true;
  }

  // ── Next Key Ciphers ─────────────────────────────────────────────────

  putNextKeyCipher(publicKey: string, cipher: EncryptedSecret): boolean {
    this.checkOpen();
    if (this.nextKeyCiphers.has(publicKey)) return false;
    this.nextKeyCiphers.set(publicKey, { ...cipher, raw: cipher.raw.slice() });
    return true;
  }

  getNextKeyCipher(publicKey: string): EncryptedSecret | null {
    this.checkOpen();
    const c = this.nextKeyCiphers.get(publicKey);
    if (!c) return null;
    return { ...c, raw: c.raw.slice() };
  }

  // ── Prefix Mapping ───────────────────────────────────────────────────

  putPrefixMapping(firstPublicKey: string, prefix: string): boolean {
    this.checkOpen();
    if (this.prefixMappings.has(firstPublicKey)) return false;
    this.prefixMappings.set(firstPublicKey, prefix);
    return true;
  }

  getPrefixMapping(firstPublicKey: string): string | null {
    this.checkOpen();
    return this.prefixMappings.get(firstPublicKey) ?? null;
  }

  pinPrefixMapping(firstPublicKey: string, prefix: string): boolean {
    this.checkOpen();
    this.prefixMappings.set(firstPublicKey, prefix);
    return true;
  }

  // ── Derivation Parameters ────────────────────────────────────────────

  putDerivationParameters(prefix: string, params: DerivationParameters): boolean {
    this.checkOpen();
    if (this.derivationParams.has(prefix)) return false;
    this.derivationParams.set(prefix, { ...params });
    return true;
  }

  getDerivationParameters(prefix: string): DerivationParameters | null {
    this.checkOpen();
    const p = this.derivationParams.get(prefix);
    return p ? { ...p } : null;
  }

  removeDerivationParameters(prefix: string): boolean {
    this.checkOpen();
    return this.derivationParams.delete(prefix);
  }

  pinDerivationParameters(prefix: string, params: DerivationParameters): boolean {
    this.checkOpen();
    this.derivationParams.set(prefix, { ...params });
    return true;
  }

  // ── Key Situation ─────────────────────────────────────────────────────

  putKeySituation(prefix: string, situation: KeySituation): boolean {
    this.checkOpen();
    if (this.keySituations.has(prefix)) return false;
    this.keySituations.set(prefix, cloneKeySituation(situation));
    return true;
  }

  getKeySituation(prefix: string): KeySituation | null {
    this.checkOpen();
    const s = this.keySituations.get(prefix);
    return s ? cloneKeySituation(s) : null;
  }

  pinKeySituation(prefix: string, situation: KeySituation): boolean {
    this.checkOpen();
    this.keySituations.set(prefix, cloneKeySituation(situation));
    return true;
  }

  // ── Public Key Sets ───────────────────────────────────────────────────

  putPublicKeySet(prefixRotationKey: string, pubSet: PublicKeySet): boolean {
    this.checkOpen();
    if (this.publicKeySets.has(prefixRotationKey)) return false;
    this.publicKeySets.set(prefixRotationKey, { pubs: [...pubSet.pubs] });
    return true;
  }

  getPublicKeySet(prefixRotationKey: string): PublicKeySet | null {
    this.checkOpen();
    const p = this.publicKeySets.get(prefixRotationKey);
    return p ? { pubs: [...p.pubs] } : null;
  }

  // ── Group Members ─────────────────────────────────────────────────────

  putSigningMembers(prefix: string, members: MemberEntry[]): boolean {
    this.checkOpen();
    if (this.signingMembersMap.has(prefix)) return false;
    this.signingMembersMap.set(prefix, members.map((m) => ({ ...m })));
    return true;
  }

  getSigningMembers(prefix: string): MemberEntry[] | null {
    this.checkOpen();
    const m = this.signingMembersMap.get(prefix);
    return m ? m.map((x) => ({ ...x })) : null;
  }

  putRotatingMembers(prefix: string, members: MemberEntry[]): boolean {
    this.checkOpen();
    if (this.rotatingMembersMap.has(prefix)) return false;
    this.rotatingMembersMap.set(prefix, members.map((m) => ({ ...m })));
    return true;
  }

  getRotatingMembers(prefix: string): MemberEntry[] | null {
    this.checkOpen();
    const m = this.rotatingMembersMap.get(prefix);
    return m ? m.map((x) => ({ ...x })) : null;
  }

  // ── Internal helpers for KeyVault re-encryption ─────────────────────

  /** Returns all stored prefixes (from derivation params). */
  allPrefixes(): string[] {
    this.checkOpen();
    return Array.from(this.derivationParams.keys());
  }

  /** Returns all stored public key entries (for re-encryption). */
  allPrivateKeyPublicKeys(): string[] {
    this.checkOpen();
    return Array.from(this.privateKeys.keys());
  }

  /** Get stored key entry (for re-encryption). */
  getRawStoredKey(publicKey: string): StoredKey | null {
    this.checkOpen();
    const k = this.privateKeys.get(publicKey);
    return k ? { ...k } : null;
  }

  /** Store a raw key entry directly (for re-encryption). */
  storeRawKey(publicKey: string, stored: StoredKey): void {
    this.checkOpen();
    this.privateKeys.set(publicKey, { ...stored });
  }
}

// ── helpers ──────────────────────────────────────────────────────────────

import type { KeySet } from "../types.js";

function cloneKeySet(ks: KeySet): KeySet {
  return { pubs: [...ks.pubs], ridx: ks.ridx, kidx: ks.kidx, dt: ks.dt };
}

function cloneKeySituation(s: KeySituation): KeySituation {
  return {
    previous: cloneKeySet(s.previous),
    current: cloneKeySet(s.current),
    next: cloneKeySet(s.next),
  };
}
