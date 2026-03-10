/** A snapshot of public keys at a specific rotation index. */
export interface KeySet {
  /** Fully qualified qb64 public keys */
  pubs: string[];
  /** Rotation index of the establishment event that introduced this key set */
  ridx: number;
  /** Starting key index in the contiguous key sequence */
  kidx: number;
  /** ISO-8601 datetime when this key set was created */
  dt: string;
}

export function makeKeySet(partial?: Partial<KeySet>): KeySet {
  return { pubs: [], ridx: 0, kidx: 0, dt: "", ...partial };
}

/** The three-phase key state for one prefix: previous, current, and next. */
export interface KeySituation {
  previous: KeySet;
  current: KeySet;
  next: KeySet;
}

export function makeKeySituation(partial?: Partial<KeySituation>): KeySituation {
  return {
    previous: makeKeySet(),
    current: makeKeySet(),
    next: makeKeySet(),
    ...partial,
  };
}

/** Parameters governing how key pairs are derived for a given prefix. */
export interface DerivationParameters {
  /** Prefix index — unique per key pair sequence across the vault */
  pidx: number;
  /** Key creation algorithm */
  algorithm: KeyAlgorithm;
  /** qb64 salt for deterministic derivation (empty for random algorithm) */
  salt: string;
  /** Path modifier used with salt for derivation */
  stem: string;
  /** Security tier for Argon2ID stretch parameters */
  tier: string;
}

export function makeDerivationParameters(
  partial?: Partial<DerivationParameters>,
): DerivationParameters {
  return {
    pidx: 0,
    algorithm: KeyAlgorithm.DETERMINISTIC,
    salt: "",
    stem: "",
    tier: SecurityTier.LOW,
    ...partial,
  };
}

/** A simple list of public keys at a given rotation index. */
export interface PublicKeySet {
  pubs: string[];
}

/** Enumeration of key creation algorithms. */
export enum KeyAlgorithm {
  RANDOM = "randy",
  DETERMINISTIC = "salty",
  GROUP = "group",
  EXTERNAL = "extern",
}

/** Argon2ID parameters for each security tier. */
export const SecurityTierParams = {
  low: { ops: 2, mem: 65536 },    // 64 MiB in KiB
  med: { ops: 3, mem: 262144 },   // 256 MiB in KiB
  high: { ops: 4, mem: 1048576 }, // 1 GiB in KiB
} as const;

/** Security tiers controlling Argon2ID stretching cost. */
export enum SecurityTier {
  LOW = "low",
  MEDIUM = "med",
  HIGH = "high",
}

/**
 * A CESR primitive holding cipher text of a secret encrypted with X25519 sealed box.
 */
export interface EncryptedSecret {
  /** Raw cipher bytes */
  raw: Uint8Array;
  /** Cipher code: "P" = X25519_Cipher_Seed, "1AAH" = X25519_Cipher_Salt */
  code: string;
  /** qb64 encoded cipher */
  qb64: string;
}
