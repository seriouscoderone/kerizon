// ── Errors ───────────────────────────────────────────────────────────
export {
  KeyStoreClosedError,
  AuthenticationError,
  DecryptionError,
  KeyNotFoundError,
  NonTransferableError,
  ThresholdError,
  DerivationError,
  DuplicatePrefixError,
  PrefixNotFoundError,
  IdentifierNotFoundError,
} from "./errors.js";

// ── Types ─────────────────────────────────────────────────────────────
export {
  KeyAlgorithm,
  SecurityTier,
  SecurityTierParams,
  makeKeySet,
  makeKeySituation,
  makeDerivationParameters,
} from "./types.js";
export type {
  KeySet,
  KeySituation,
  DerivationParameters,
  PublicKeySet,
  EncryptedSecret,
} from "./types.js";

// ── Config ────────────────────────────────────────────────────────────
export { DEFAULT_VAULT_CONFIG } from "./config.js";
export type { VaultConfig } from "./config.js";

// ── CESR Helpers ──────────────────────────────────────────────────────
export {
  MtrDex,
  matterEncode,
  matterDecode,
  makeVerfer,
  verferFromQb64,
  makeDiger,
  digerFromQb64,
  encodeIndexedSig,
  makeEncryptedSecretFromRaw,
  encryptedSecretFromQb64,
} from "./cesr-helpers.js";
export type { Verfer, Diger, IndexedSig, UnindexedSig } from "./cesr-helpers.js";

// ── SigningKey ────────────────────────────────────────────────────────
export { makeSigningKey, signingKeyFromQb64 } from "./signing-key.js";
export type { SigningKey } from "./signing-key.js";

// ── Ports ─────────────────────────────────────────────────────────────
export type { ICryptographicSuite } from "./ports/cryptographic-suite.js";
export type { IKeyStore, ISecretEncryptor, ISecretDecryptor, MemberEntry } from "./ports/key-store.js";

// ── Adapters ──────────────────────────────────────────────────────────
export { DefaultCryptographicSuite } from "./adapters/default-crypto-suite.js";

// ── Memory ────────────────────────────────────────────────────────────
export { InMemoryKeyStore } from "./memory/in-memory-key-store.js";

// ── Key Derivation ────────────────────────────────────────────────────
export { KeyDeriver } from "./derivation/key-deriver.js";
export {
  RandomKeyGenerator,
  DeterministicKeyGenerator,
  KeyGeneratorFactory,
} from "./derivation/strategy.js";
export type { IKeyGenerationStrategy } from "./derivation/strategy.js";

// ── Encryption ────────────────────────────────────────────────────────
export { SecretEncryptor } from "./encryption/secret-encryptor.js";
export { SecretDecryptor } from "./encryption/secret-decryptor.js";

// ── Key Vault ─────────────────────────────────────────────────────────
export { KeyVault } from "./key-vault.js";

// ── Views ─────────────────────────────────────────────────────────────
export { KeyInventory } from "./views/key-inventory.js";

// ── Builders ─────────────────────────────────────────────────────────
export { InceptionKeySetBuilder } from "./builders/inception-keys.js";
export { RotationKeySetBuilder } from "./builders/rotation-keys.js";
export { GroupKeySetBuilder } from "./builders/group-keys.js";
export type { MemberKeyState } from "./builders/group-keys.js";

// ── Aggregate Roots ───────────────────────────────────────────────────
export { IdentifierContext } from "./identifier-context.js";
export { GroupIdentifierContext } from "./group-context.js";
export { IdentifierRegistry } from "./identifier-registry.js";
