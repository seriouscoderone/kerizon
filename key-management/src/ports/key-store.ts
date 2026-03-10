/**
 * KeyStore port interface — abstract persistence boundary for key material.
 */
import type { SigningKey } from "../signing-key.js";
import type { EncryptedSecret, DerivationParameters, KeySituation, PublicKeySet } from "../types.js";

// Forward-reference types (resolved at runtime)
export interface ISecretEncryptor {
  encrypt(
    ser?: Uint8Array,
    prim?: { raw: Uint8Array; qb64: string; code: string },
    code?: string,
  ): EncryptedSecret;
  raw: Uint8Array;
  qb64: string;
}

export interface ISecretDecryptor {
  decrypt(
    cipher?: EncryptedSecret,
    qb64?: string,
    klas?: "salt" | "seed",
    transferable?: boolean,
    bare?: boolean,
  ): unknown;
  raw: Uint8Array;
  qb64: string;
}

/** Simple prefix+sequenceNumber pair for group membership. */
export interface MemberEntry {
  prefix: string;
  sequenceNumber: number;
}

/** Abstract persistence boundary for key material. */
export interface IKeyStore {
  // ── Lifecycle ───────────────────────────────────────────────────────
  open(): void;
  close(): void;
  isOpened(): boolean;

  // ── Globals ──────────────────────────────────────────────────────────
  getGlobal(key: string): string | null;
  putGlobal(key: string, value: string): void;
  pinGlobal(key: string, value: string): void;

  // ── Private Keys ─────────────────────────────────────────────────────
  putPrivateKey(
    publicKey: string,
    signer: SigningKey,
    encrypter: ISecretEncryptor | null,
  ): boolean;
  getPrivateKey(
    publicKey: string,
    decrypter: ISecretDecryptor | null,
  ): SigningKey | null;
  removePrivateKey(publicKey: string): boolean;
  pinPrivateKey(
    publicKey: string,
    signer: SigningKey,
    encrypter: ISecretEncryptor | null,
  ): boolean;

  // ── Next Key Ciphers ─────────────────────────────────────────────────
  putNextKeyCipher(publicKey: string, cipher: EncryptedSecret): boolean;
  getNextKeyCipher(publicKey: string): EncryptedSecret | null;

  // ── Prefix Mapping ───────────────────────────────────────────────────
  putPrefixMapping(firstPublicKey: string, prefix: string): boolean;
  getPrefixMapping(firstPublicKey: string): string | null;
  pinPrefixMapping(firstPublicKey: string, prefix: string): boolean;

  // ── Derivation Parameters ────────────────────────────────────────────
  putDerivationParameters(prefix: string, params: DerivationParameters): boolean;
  getDerivationParameters(prefix: string): DerivationParameters | null;
  removeDerivationParameters(prefix: string): boolean;
  pinDerivationParameters(prefix: string, params: DerivationParameters): boolean;

  // ── Key Situation ─────────────────────────────────────────────────────
  putKeySituation(prefix: string, situation: KeySituation): boolean;
  getKeySituation(prefix: string): KeySituation | null;
  pinKeySituation(prefix: string, situation: KeySituation): boolean;

  // ── Public Key Sets ───────────────────────────────────────────────────
  putPublicKeySet(prefixRotationKey: string, pubSet: PublicKeySet): boolean;
  getPublicKeySet(prefixRotationKey: string): PublicKeySet | null;

  // ── Group Members ─────────────────────────────────────────────────────
  putSigningMembers(prefix: string, members: MemberEntry[]): boolean;
  getSigningMembers(prefix: string): MemberEntry[] | null;
  putRotatingMembers(prefix: string, members: MemberEntry[]): boolean;
  getRotatingMembers(prefix: string): MemberEntry[] | null;
}
