# Key Management Library Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Purpose:** Language-agnostic specification for a standalone Key Management library (BC-2), suitable for generating conformant implementations in any language.
**Normative basis:** [KERI Specification](https://trustoverip.github.io/kswg-keri-specification/), [CESR Specification](https://trustoverip.github.io/kswg-cesr-specification/)
**Cross-checked against:** keripy reference implementation (`src/keri/app/keeping.py`, `src/keri/core/signing.py`, `src/keri/app/habbing.py`, `src/keri/kering.py`)
**Depends on:** [KEL Event Processing Library (BC-1)](kel-event-processing-lib.md)

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Types and Constants](#2-types-and-constants)
3. [Error Hierarchy](#3-error-hierarchy)
4. [Port Interfaces](#4-port-interfaces)
5. [Key Derivation](#5-key-derivation)
6. [Encryption and Decryption](#6-encryption-and-decryption)
7. [Key Generation Strategies](#7-key-generation-strategies)
8. [Builders](#8-builders)
9. [Views](#9-views)
10. [KeyVault — Aggregate Root](#10-keyvault--aggregate-root)
11. [IdentifierContext — Aggregate Root](#11-identifiercontext--aggregate-root)
12. [IdentifierRegistry — Aggregate Root / Factory](#12-identifierregistry--aggregate-root--factory)
13. [GroupIdentifierContext — Aggregate Root](#13-groupidentifiercontext--aggregate-root)
14. [Invariant Contract](#14-invariant-contract)
15. [Configuration](#15-configuration)
16. [Test Specification](#16-test-specification)
- [Appendix A: Usage Examples](#appendix-a-usage-examples)
- [Appendix B: DDD Name Mapping](#appendix-b-ddd-name-mapping)
- [Appendix C: Wire-Format Field Reference](#appendix-c-wire-format-field-reference)

---

## 1. Purpose and Scope

This specification defines the public API, invariants, and behavioral contract of a standalone Key Management library. An implementation of this spec manages private key lifecycle — creation, deterministic derivation, encrypted storage, rotation, signing, and decryption — for KERI identifiers. It is the second bounded context (BC-2) in the KERI domain decomposition and depends on BC-1 (KEL Event Processing) for key state and event construction.

### In scope

- **KeyVault** (aggregate root): central authority for all private key operations — one per process
- **IdentifierContext** (aggregate root): one AID lifecycle combining KeyVault and BC-1 key state
- **IdentifierRegistry** (aggregate root / factory): multi-AID environment with shared resources
- **GroupIdentifierContext** (aggregate root): multi-sig partial-signature coordination per participant
- **KeyDeriver** (domain service): deterministic key derivation from salt via Argon2ID stretching
- **SecretEncryptor / SecretDecryptor** (domain services): X25519 sealed box encrypt/decrypt
- **Key generation strategies**: RandomKeyGenerator, DeterministicKeyGenerator, KeyGeneratorFactory
- **Builders**: InceptionKeySetBuilder, RotationKeySetBuilder, GroupKeySetBuilder
- **Views**: KeyInventory (read-only query interface)
- **KeyStore** (repository interface): abstract persistence boundary for key material
- **CryptographicSuite** (port interface): abstract boundary for cryptographic operations
- **Three-phase rotation lifecycle**: previous ← current ← next key set advancement
- **AEID authentication**: non-transferable AID-based vault access control and secret encryption

### Out of scope

This specification does **not** cover:

- Event processing logic (defined by BC-1 — KEL Event Processing Library)
- Networking (transport, parsing streams, message framing)
- TEL (Transaction Event Log) or ACDC (Authentic Chained Data Containers)
- Exchange protocol (`exn` messages)
- OOBI (Out-of-Band Introduction) resolution
- Reply messages (`rpy`, `qry`)
- Framework dependencies (no hio, falcon, asyncio, or equivalent)

### Shared kernel (assumed given)

CESR primitives are a shared kernel dependency, not redefined here:

- **Prefixer** — qualified AID prefix
- **Diger** — qualified digest
- **Verfer** — qualified public verification key
- **Siger** — indexed signature
- **Cigar** — unindexed signature
- **Tholder** — threshold holder (simple integer or weighted fractional)
- **Serder** — self-addressing data serializer/deserializer
- **Number** — qualified sequence number
- **Dater** — qualified ISO-8601 datetime
- **Saider** — SAID (Self-Addressing Identifier) computation
- **Matter** — base class for all qualified cryptographic material

### BC-1 dependency surface

The following types from the [KEL Event Processing Library](kel-event-processing-lib.md) are imported, not redefined:

- **IdentifierState** — aggregate root for one AID's key state
- **EventProcessor** — domain service for event dispatch
- **EventRepository** — abstract persistence boundary for events
- **KeyStateSnapshot** — serializable key state projection
- **InceptionBuilder, RotationBuilder, InteractionBuilder** — event construction
- **SignedEvent** — event + signatures composition
- **DomainEventBus** — typed output signals

---

## 2. Types and Constants

### 2.1 KeySet

A snapshot of public keys at a specific rotation index within a key sequence.

Cross-ref: `keeping.py:42` (`PubLot`)

| Field | Type | Description |
|-------|------|-------------|
| `pubs` | list[str] | Fully qualified qb64 public keys |
| `ridx` | int | Rotation index of the establishment event that introduced this key set (inception = 0) |
| `kidx` | int | Starting key index in the contiguous key sequence (e.g., ridx 2 with 3 keys/set → kidx 6) |
| `dt` | str | ISO-8601 datetime when this key set was created |

### 2.2 KeySituation

The three-phase key state for one prefix: previous, current, and next key sets.

Cross-ref: `keeping.py:66` (`PreSit`)

| Field | Type | Description |
|-------|------|-------------|
| `previous` | KeySet | Prior key set (from the establishment event before the current one) |
| `current` | KeySet | Currently active signing key set |
| `next` | KeySet | Pre-committed next key set (for the next rotation) |

### 2.3 DerivationParameters

Parameters governing how key pairs are derived for a given prefix.

Cross-ref: `keeping.py:79` (`PrePrm`)

| Field | Type | Description |
|-------|------|-------------|
| `pidx` | int | Prefix index — unique per key pair sequence across the vault |
| `algorithm` | KeyAlgorithm | Key creation algorithm (random, deterministic, group, external) |
| `salt` | str | qb64 salt for deterministic derivation (empty for random algorithm); may be encrypted |
| `stem` | str | Path modifier used with salt for derivation; defaults to hex of `pidx` |
| `tier` | str | Security tier for Argon2ID stretch parameters |

### 2.4 PublicKeySet

A simple list of public keys at a given rotation index, enabling replay lookups.

Cross-ref: `keeping.py:94` (`PubSet`)

| Field | Type | Description |
|-------|------|-------------|
| `pubs` | list[str] | Fully qualified qb64 public keys |

### 2.5 KeyAlgorithm

Enumeration of key creation algorithms.

Cross-ref: `keeping.py:38` (`Algos`)

| Constant | Wire Value | Description |
|----------|-----------|-------------|
| `RANDOM` | `"randy"` | Each key pair uses fresh random entropy |
| `DETERMINISTIC` | `"salty"` | Key pairs derived deterministically from salt + path |
| `GROUP` | `"group"` | Group multi-sig; keys contributed by member identifiers |
| `EXTERNAL` | `"extern"` | Key pairs generated and managed externally (import/recovery) |

### 2.6 SecurityTier

Security tiers controlling Argon2ID stretching cost.

Cross-ref: `signing.py:28` (`Tiers`)

| Constant | Wire Value | Argon2ID ops | Argon2ID memory | Description |
|----------|-----------|-------------|-----------------|-------------|
| `LOW` | `"low"` | 2 | 64 MiB | Interactive — fast key creation |
| `MEDIUM` | `"med"` | 3 | 256 MiB | Moderate — balanced security |
| `HIGH` | `"high"` | 4 | 1 GiB | Sensitive — maximum stretch cost |

**Test mode:** When `testMode` is true, stretching uses minimal parameters (ops=1, mem=8 KiB) regardless of tier, enabling fast test execution.

### 2.7 EncryptedSecret

A CESR primitive (Matter subtype) holding cipher text of a secret (private key seed or salt). The cipher code indicates what type of plaintext has been encrypted. Encrypted with X25519 sealed box.

Cross-ref: `signing.py:655` (`Cipher`)

| Cipher Code | Plaintext Type | Description |
|-------------|---------------|-------------|
| `X25519_Cipher_Seed` (`"P"`) | Ed25519 private key seed (44 char qb64) | Fixed size 124 char qb64 cipher |
| `X25519_Cipher_Salt` (`"1AAH"`) | 128-bit salt (24 char qb64) | Fixed size 100 char qb64 cipher |
| `X25519_Cipher_QB64_L*` | Variable qb64 plaintext | Variable size cipher, lead 0/1/2 |
| `X25519_Cipher_L*` | Sniffable CESR stream | Variable size cipher for stream plaintext |

### 2.8 AuthenticationIdentifier

A non-transferable AID prefix used for vault authentication and secret encryption. The associated Ed25519 key pair is converted to X25519 for sealed box encryption/decryption. The AEID is stored in the KeyStore; its seed (private key) is held in memory only and MUST NOT be persisted.

---

## 3. Error Hierarchy

Each error type maps to a specific failure mode in key management operations.

Cross-ref: `kering.py:413–458` (`ClosedError`, `AuthError`, `DecryptError`), `kering.py:714` (`DerivationError`)

| Error Type | Extends | Trigger Condition | Cross-ref |
|------------|---------|-------------------|-----------|
| `KeyStoreClosedError` | base | KeyStore database not open when operation attempted | `kering.py:413` |
| `AuthenticationError` | base | AEID seed missing or does not match stored AEID | `kering.py:431` |
| `DecryptionError` | AuthenticationError | AEID is set but no decrypter available; unauthorized decryption | `kering.py:458` |
| `KeyNotFoundError` | base | Private key not found in KeyStore for given public key | — |
| `NonTransferableError` | base | Rotation attempted on identifier with empty next key set | — |
| `ThresholdError` | base | Signing threshold not met or index validation failed | — |
| `DerivationError` | base | Invalid key derivation parameters (unsupported code, bad salt) | `kering.py:714` |
| `DuplicatePrefixError` | base | Prefix already exists in KeyStore during inception | — |
| `PrefixNotFoundError` | base | Prefix not found in KeyStore for rotation/sign/query | — |
| `IdentifierNotFoundError` | base | Named identifier not found in IdentifierRegistry | — |

### Error flow

```
KeyVault.inceptKeys(...)
    │
    ├── KeyStore not open          → KeyStoreClosedError
    ├── prefix already exists      → DuplicatePrefixError
    ├── bad derivation code        → DerivationError
    └── success                    → (verfers, digers)

KeyVault.signSerialization(...)
    │
    ├── AEID set, no decrypter     → DecryptionError
    ├── public key not in store    → KeyNotFoundError
    ├── index mismatch             → ThresholdError
    └── success                    → list[Siger|Cigar]

KeyVault.rotateKeys(...)
    │
    ├── prefix not found           → PrefixNotFoundError
    ├── empty next keys            → NonTransferableError
    ├── AEID set, no decrypter     → DecryptionError
    └── success                    → (verfers, digers)
```

---

## 4. Port Interfaces

Port interfaces abstract external dependencies behind domain-language contracts. Implementations provide concrete adapters.

### 4.1 CryptographicSuite

Abstracts all cryptographic primitives. In keripy these are direct calls to pysodium and `cryptography` scattered across `signing.py`, `coring.py`, and `keeping.py`.

Cross-ref: `signing.py:10` (pysodium import), `signing.py:12–14` (cryptography imports)

```
CryptographicSuite (port interface)

    Key Pair Derivation:
        deriveEdKeyPair(seed: bytes) → (publicKey: bytes, signingKey: bytes)
            Derives Ed25519 key pair from 32-byte seed.
            Cross-ref: pysodium.crypto_sign_seed_keypair

        deriveEcKeyPair(seed: bytes, curve: str) → (publicKey: bytes, signingKey: bytes)
            Derives ECDSA key pair from seed on named curve ("secp256r1" or "secp256k1").
            Cross-ref: cryptography.hazmat ec.derive_private_key

    Signing:
        edSign(message: bytes, signingKey: bytes) → bytes
            Ed25519 detached signature.
            Cross-ref: pysodium.crypto_sign_detached

        ecSign(message: bytes, seed: bytes, curve: str) → bytes
            ECDSA detached signature (r || s, 64 bytes).
            Cross-ref: cryptography.hazmat ec.ECDSA

    Key Stretching:
        stretchKey(password: bytes, salt: bytes, outLength: int,
                   opsLimit: int, memLimit: int) → bytes
            Argon2ID key stretching.
            Cross-ref: pysodium.crypto_pwhash (ALG_ARGON2ID13)

    Random Generation:
        generateRandom(size: int) → bytes
            Cryptographically secure random bytes.
            Cross-ref: pysodium.randombytes

    Sealed Box Encryption:
        sealedBoxEncrypt(plaintext: bytes, publicKey: bytes) → bytes
            X25519 sealed box encryption.
            Cross-ref: pysodium.crypto_box_seal

        sealedBoxDecrypt(ciphertext: bytes, publicKey: bytes, privateKey: bytes) → bytes
            X25519 sealed box decryption.
            Cross-ref: pysodium.crypto_box_seal_open

    Key Conversion:
        edPublicToX25519(edPublicKey: bytes) → bytes
            Converts Ed25519 public key to X25519 public key.
            Cross-ref: pysodium.crypto_sign_pk_to_box_pk

        edPrivateToX25519(edSigningKey: bytes) → bytes
            Converts Ed25519 signing key (seed + verkey, 64 bytes) to X25519 private key.
            Cross-ref: pysodium.crypto_sign_sk_to_box_sk

        x25519Base(privateKey: bytes) → bytes
            Computes X25519 public key from private key (scalar base multiplication).
            Cross-ref: pysodium.crypto_scalarmult_curve25519_base
```

### 4.2 KeyStore

Abstract persistence boundary for key material. In keripy this is `Keeper` backed by LMDB.

Cross-ref: `keeping.py:133` (`Keeper`), sub-databases at `keeping.py:267–292`

```
KeyStore (repository interface)

    Lifecycle:
        open() → void
            Opens the underlying storage. All other methods require open state.
        close() → void
            Closes storage. May optionally clear temporary data.
        isOpened() → bool
            Returns true if storage is open.

    Globals (vault-wide parameters):
        getGlobal(key: str) → str | null
            Retrieves a global parameter by label.
            Labels: "aeid", "pidx", "algo", "salt", "tier"
            Cross-ref: keeping.py:267 (gbls sub-db)
        putGlobal(key: str, value: str) → void
            Stores a global parameter. Overwrites if exists.
        pinGlobal(key: str, value: str) → void
            Stores or updates a global parameter (upsert).

    Private Keys:
        putPrivateKey(publicKey: str, signer: SigningKey, encrypter: SecretEncryptor | null) → bool
            Stores a private key indexed by its corresponding public key.
            When encrypter is provided, the private key is encrypted before storage.
            Returns false if key already exists.
            Cross-ref: keeping.py:268 (pris sub-db, CryptSignerSuber)
        getPrivateKey(publicKey: str, decrypter: SecretDecryptor | null) → SigningKey | null
            Retrieves and optionally decrypts a private key by its public key.
            Returns null if not found.
        removePrivateKey(publicKey: str) → bool
            Removes a private key entry. Returns false if not found.
        pinPrivateKey(publicKey: str, signer: SigningKey, encrypter: SecretEncryptor | null) → bool
            Stores or overwrites a private key (upsert).

    Next Key Ciphers:
        putNextKeyCipher(publicKey: str, cipher: EncryptedSecret) → bool
            Stores an encrypted next-key cipher indexed by public key.
            Cross-ref: keeping.py:272 (nxts sub-db)
        getNextKeyCipher(publicKey: str) → EncryptedSecret | null
            Retrieves a next-key cipher.

    Prefix Mapping:
        putPrefixMapping(firstPublicKey: str, prefix: Prefixer) → bool
            Maps the first public key to its prefix (temporary until movePrefix).
            Cross-ref: keeping.py:281 (pres sub-db)
        getPrefixMapping(firstPublicKey: str) → Prefixer | null
            Returns the prefix associated with a first public key.
        pinPrefixMapping(firstPublicKey: str, prefix: Prefixer) → bool
            Overwrites the prefix mapping (upsert).

    Derivation Parameters:
        putDerivationParameters(prefix: str, params: DerivationParameters) → bool
            Stores derivation parameters for a prefix.
            Cross-ref: keeping.py:284 (prms sub-db)
        getDerivationParameters(prefix: str) → DerivationParameters | null
        removeDerivationParameters(prefix: str) → bool
        pinDerivationParameters(prefix: str, params: DerivationParameters) → bool

    Key Situation:
        putKeySituation(prefix: str, situation: KeySituation) → bool
            Stores the three-phase key situation for a prefix.
            Cross-ref: keeping.py:287 (sits sub-db)
        getKeySituation(prefix: str) → KeySituation | null
        pinKeySituation(prefix: str, situation: KeySituation) → bool

    Public Key Sets:
        putPublicKeySet(prefixRotationKey: str, pubSet: PublicKeySet) → bool
            Stores public key set at compound key = prefix + "." + rotationIndex (32 char hex).
            Cross-ref: keeping.py:290 (pubs sub-db)
        getPublicKeySet(prefixRotationKey: str) → PublicKeySet | null

    Group Members:
        putSigningMembers(prefix: str, members: list[tuple[Prefixer, Number]]) → bool
            Stores signing member identifiers and sequence numbers for a group prefix.
            Cross-ref: keeping.py:275 (smids sub-db)
        getSigningMembers(prefix: str) → list[tuple[Prefixer, Number]] | null
        putRotatingMembers(prefix: str, members: list[tuple[Prefixer, Number]]) → bool
            Stores rotating member identifiers for a group prefix.
            Cross-ref: keeping.py:278 (rmids sub-db)
        getRotatingMembers(prefix: str) → list[tuple[Prefixer, Number]] | null
```

---

## 5. Key Derivation

### 5.1 KeyDeriver

KeyDeriver wraps a 128-bit random salt and provides deterministic key derivation through Argon2ID key stretching. Given identical salt, path, and tier, the derived key pair is always the same — enabling recovery without persisting private keys.

Cross-ref: `signing.py:329` (`Salter`)

**Construction:**

```
KeyDeriver(raw: bytes | null, qb64: str | null, tier: SecurityTier | null)
```

- If neither `raw` nor `qb64` provided, generates a fresh random 16-byte salt via `CryptographicSuite.generateRandom(16)`.
- `raw` must be exactly 16 bytes when provided.
- `tier` defaults to `SecurityTier.LOW`.
- Inherits from CESR `Matter` with code `Salt_128`.

**Path construction:**

Deterministic paths combine stem, rotation index, and key index:

```
path = "{stem}{ridx:x}{kidx:x}"
```

When `stem` is not explicitly set, it defaults to `"{pidx:x}"` where `pidx` is the prefix index. This ensures every prefix derives unique keys from the same root salt.

Cross-ref: `keeping.py:525–527` (SaltyCreator path construction)

**Core method — stretch:**

```
stretch(size: int, path: str, tier: SecurityTier | null, testMode: bool) → bytes
```

Returns `size` bytes of raw key material derived from `path` and the salter's raw salt via Argon2ID.

Cross-ref: `signing.py:411` (`Salter.stretch`)

| Parameter | Description |
|-----------|-------------|
| `size` | Number of output bytes (typically 32 for Ed25519 seed) |
| `path` | Unique string differentiating each key in the sequence |
| `tier` | Security tier; defaults to the KeyDeriver's tier |
| `testMode` | True uses minimal stretch (ops=1, mem=8KiB) for fast testing |

**Derived method — signer:**

```
signer(code: str, transferable: bool, path: str, tier: SecurityTier | null, testMode: bool) → SigningKey
```

Stretches salt to `Matter.rawSize(code)` bytes, then wraps in a `SigningKey` (CESR `Signer`).

Cross-ref: `signing.py:450` (`Salter.signer`)

**Batch method — signers:**

```
signers(count: int, start: int, path: str, ...) → list[SigningKey]
```

Creates `count` signers with paths `"{path}{start+0:x}"`, `"{path}{start+1:x}"`, etc.

Cross-ref: `signing.py:471` (`Salter.signers`)

---

## 6. Encryption and Decryption

### 6.1 SecretEncryptor

Encrypts secrets (private key seeds or salts) using X25519 sealed box encryption. The encryption public key is derived from an Ed25519 verification key (the AEID public key).

Cross-ref: `signing.py:750` (`Encrypter`)

**Construction:**

```
SecretEncryptor(raw: bytes | null, verkey: str | null)
```

- If `verkey` provided (Ed25519 public key qb64), converts to X25519 public key via `CryptographicSuite.edPublicToX25519`.
- Verkey must have code `Ed25519` or `Ed25519N`.
- Inherits from CESR `Matter` with code `X25519`.

**Methods:**

```
encrypt(ser: bytes | null, prim: Matter | null, code: str | null) → EncryptedSecret
```

Encrypts either a raw serialization (`ser`) or a CESR primitive (`prim`). When encrypting a primitive:

- `Salt_128` → uses cipher code `X25519_Cipher_Salt`
- `Ed25519_Seed` → uses cipher code `X25519_Cipher_Seed`
- Other → requires explicit `code`

Cross-ref: `signing.py:817` (`Encrypter.encrypt`)

```
verifySeed(seed: str) → bool
```

Verifies that a signing seed corresponds to the public key used to derive this encryptor's X25519 key. Used for AEID authentication.

Cross-ref: `signing.py:801` (`Encrypter.verifySeed`)

### 6.2 SecretDecryptor

Decrypts secrets using X25519 sealed box decryption. The decryption private key is derived from an Ed25519 signing key seed.

Cross-ref: `signing.py:885` (`Decrypter`)

**Construction:**

```
SecretDecryptor(seed: str | null, raw: bytes | null)
```

- If `seed` provided (Ed25519 private signing key seed qb64), derives X25519 private key:
  1. Reconstruct signing key: `sigkey = seed.raw + seed.verfer.raw` (64 bytes)
  2. Convert: `CryptographicSuite.edPrivateToX25519(sigkey)`
- Inherits from CESR `Matter` with code `X25519_Private`.

**Methods:**

```
decrypt(cipher: EncryptedSecret | null, qb64: str | null, klas: type | null,
        transferable: bool, bare: bool) → Matter | bytes
```

Decrypts cipher text. When `klas` is null, the return type is inferred from the cipher code:

- `X25519_Cipher_Salt` → returns KeyDeriver (Salter)
- `X25519_Cipher_Seed` → returns SigningKey (Signer)
- Stream cipher codes → returns Streamer

When `bare` is true, returns raw decrypted bytes instead of a typed instance.

Cross-ref: `signing.py:949` (`Decrypter.decrypt`)

### 6.3 AEID Authentication Flow

The Authentication and Encryption IDentifier (AEID) is a non-transferable AID prefix whose key pair controls vault access:

1. **Setup:** Vault receives AEID (public) and seed (private). SecretEncryptor is derived from AEID. SecretDecryptor is derived from seed.
2. **Verification:** `SecretEncryptor.verifySeed(seed)` confirms the seed matches the AEID.
3. **Encryption on write:** All private keys and per-prefix salts are encrypted via SecretEncryptor before storage.
4. **Decryption on read:** Private keys and salts are decrypted via SecretDecryptor on retrieval.
5. **Re-encryption on AEID change:** When AEID changes, all secrets are decrypted with old decrypter and re-encrypted with new encrypter.
6. **Seed never persisted:** The seed is held in memory only. It MUST NOT be written to the KeyStore.

Cross-ref: `keeping.py:609–618` (Manager._seed documentation), `keeping.py:763` (Manager.updateAeid)

---

## 7. Key Generation Strategies

### 7.1 KeyGenerationStrategy (interface)

Abstract interface for key pair creation algorithms.

Cross-ref: `keeping.py:357` (`Creator`)

```
KeyGenerationStrategy

    create(codes: list[str] | null, count: int, code: str,
           pidx: int, ridx: int, kidx: int,
           transferable: bool, testMode: bool) → list[SigningKey]

    Properties (read-only):
        salt → str       (empty for non-deterministic strategies)
        stem → str       (empty for non-deterministic strategies)
        tier → str       (empty for non-deterministic strategies)
```

| Parameter | Description |
|-----------|-------------|
| `codes` | Explicit list of derivation codes, one per key; overrides `count`/`code` |
| `count` | Number of key pairs when `codes` not provided |
| `code` | Default derivation code for all keys when `codes` not provided |
| `pidx` | Prefix index (used by deterministic strategy for path construction) |
| `ridx` | Rotation index (used by deterministic strategy for path construction) |
| `kidx` | Starting key index (used by deterministic strategy for path construction) |
| `transferable` | True means transferable derivation code for public keys |
| `testMode` | True means minimal stretch for testing |

### 7.2 RandomKeyGenerator

Each key pair uses fresh random entropy. No deterministic recovery possible.

Cross-ref: `keeping.py:408` (`RandyCreator`)

```
RandomKeyGenerator

    create(codes, count, code, transferable, ...) → list[SigningKey]
```

Ignores `pidx`, `ridx`, `kidx`, `testMode`. For each code in the resolved codes list, creates a new `SigningKey` with fresh random raw material.

### 7.3 DeterministicKeyGenerator

Key pairs derived deterministically from salt + path via KeyDeriver. Same inputs always produce the same key pairs.

Cross-ref: `keeping.py:452` (`SaltyCreator`)

**Construction:**

```
DeterministicKeyGenerator(salt: str | null, stem: str | null, tier: SecurityTier | null)
```

Creates an internal `KeyDeriver` from the provided salt.

**Key creation:**

```
create(codes, count, code, pidx, ridx, kidx, transferable, testMode) → list[SigningKey]
```

For each code at offset `i`:

1. Resolve stem: if `stem` is empty, use `"{pidx:x}"`
2. Construct path: `"{stem}{ridx:x}{kidx+i:x}"`
3. Call `keyDeriver.signer(path=path, code=code, transferable=transferable, tier=tier, testMode=testMode)`

Cross-ref: `keeping.py:505–533` (`SaltyCreator.create`)

### 7.4 KeyGeneratorFactory

Factory that creates the appropriate strategy instance based on algorithm.

Cross-ref: `keeping.py:536` (`Creatory`)

```
KeyGeneratorFactory(algorithm: KeyAlgorithm)

    make(salt: str | null, stem: str | null, tier: SecurityTier | null) → KeyGenerationStrategy
```

| Algorithm | Strategy Created |
|-----------|-----------------|
| `RANDOM` | `RandomKeyGenerator()` |
| `DETERMINISTIC` | `DeterministicKeyGenerator(salt, stem, tier)` |
| `GROUP` | (not instantiated via factory — handled by GroupIdentifierContext) |
| `EXTERNAL` | (not instantiated via factory — handled by ingestExternalKeys) |

---

## 8. Builders

Builders are pure functions — no repository access, no side effects. They collect configuration and produce key material on `.build()`.

### 8.1 InceptionKeySetBuilder

Configures initial key pairs for a new identifier and invokes the KeyVault to produce verfers and digers.

Cross-ref: `keeping.py:928` (`Manager.incept`)

```
InceptionKeySetBuilder
    .algorithm(algo: KeyAlgorithm)          — key creation algorithm (default: vault default)
    .salt(salt: str)                        — qb64 salt for deterministic algo
    .stem(stem: str)                        — path modifier for deterministic algo
    .tier(tier: SecurityTier)               — security tier for stretching
    .rooted(rooted: bool)                   — true (default) means inherit salt/algo/tier from vault root
    .currentCount(count: int)               — number of inception signing keys (default: 1)
    .currentCodes(codes: list[str])         — explicit derivation codes per key
    .nextCount(count: int)                  — number of next rotation keys (default: 1)
    .nextCodes(codes: list[str])            — explicit derivation codes per next key
    .digestCode(code: str)                  — digest code for next key digests (default: Blake3_256)
    .transferable(transferable: bool)       — true (default) means transferable prefix
    .testMode(testMode: bool)               — true means minimal stretch
    .build(vault: KeyVault) → (verfers: list[Verfer], digers: list[Diger])
```

**Build-time behavior:**

1. Resolves algorithm, salt, tier from vault root when `rooted` is true and not explicitly set
2. Allocates next `pidx` from vault
3. Creates strategy via `KeyGeneratorFactory(algorithm).make(salt, stem, tier)`
4. Generates current signing keys at `ridx=0`, `kidx=0`
5. Generates next keys at `ridx=1`, `kidx=len(currentKeys)`
6. Computes digers: `Diger(ser=signer.verfer.qb64b, code=digestCode)` for each next signer
7. Stores DerivationParameters, KeySituation, prefix mapping, private keys in KeyStore
8. Returns `(verfers, digers)`

**Build-time validation:**

1. `currentCount` MUST be > 0 (or `currentCodes` non-empty)
2. `nextCount` MUST be ≥ 0 (0 means non-transferable in effect)
3. Algorithm MUST be `RANDOM` or `DETERMINISTIC`
4. Prefix (first public key) MUST NOT already exist in KeyStore

### 8.2 RotationKeySetBuilder

Configures key rotation for an existing identifier and invokes the KeyVault.

Cross-ref: `keeping.py:1121` (`Manager.rotate`)

```
RotationKeySetBuilder
    .forIdentifier(prefix: str)             — identifies which prefix to rotate
    .nextCount(count: int)                  — number of new next keys (default: 1)
    .nextCodes(codes: list[str])            — explicit derivation codes per new next key
    .digestCode(code: str)                  — digest code for new next key digests
    .transferable(transferable: bool)       — true (default) means transferable codes
    .eraseStaleKeys(erase: bool)            — true (default) means erase prior-old private keys
    .testMode(testMode: bool)               — true means minimal stretch
    .build(vault: KeyVault) → (verfers: list[Verfer], digers: list[Diger])
```

**Build-time behavior:**

1. Loads DerivationParameters and KeySituation from KeyStore for `prefix`
2. Advances three-phase state: `previous ← current`, `current ← next`, `next ← new`
3. Verfers come from the now-current keys (which were the prior next keys)
4. Creates strategy from stored parameters
5. Generates new next keys at `ridx = current.ridx + 1`, `kidx = next.kidx + len(current.pubs)`
6. Computes digers for new next keys
7. Updates KeySituation in KeyStore
8. Stores new private keys
9. If `eraseStaleKeys` is true, removes private keys from the prior previous set
10. Returns `(verfers, digers)`

**Build-time validation:**

1. Prefix MUST exist in KeyStore
2. Current next key set MUST NOT be empty (else NonTransferableError)
3. Private keys for current-becoming-now keys MUST be retrievable
4. `nextCount` MUST be ≥ 0

### 8.3 GroupKeySetBuilder

Assembles signing and rotating key sets from multiple group members' contributions.

Cross-ref: `habbing.py:2622` (`GroupHab`), `habbing.py:633` (`extractMerfersMigers`)

```
GroupKeySetBuilder
    .addSigningMember(prefix: str, sequenceNumber: int)
    .addRotatingMember(prefix: str, sequenceNumber: int)
    .signingThreshold(threshold: str | int | list)
    .nextThreshold(threshold: str | int | list)
    .build() → (verfers: list[Verfer], digers: list[Diger])
```

**Build-time behavior:**

1. For each signing member, extracts current signing keys from their key state
2. For each rotating member, extracts next key digests from their key state
3. Concatenates verfers in member order
4. Concatenates digers in member order
5. Validates thresholds against resulting key counts

---

## 9. Views

### 9.1 KeyInventory

Read-only query interface over the KeyStore, providing domain-language access to key material state.

Cross-ref: `keeping.py:594–643` (Manager properties)

```
KeyInventory (read-only view)

    identifiers() → list[str]
        All prefix strings managed by this vault.

    keySituation(prefix: str) → KeySituation
        Three-phase key state for a prefix.

    derivationParameters(prefix: str) → DerivationParameters
        Derivation parameters for a prefix.

    isManaged(prefix: str) → bool
        True if prefix exists in KeyStore.

    currentSigningKeys(prefix: str) → list[str]
        Public keys from current key set (shorthand for keySituation.current.pubs).

    nextKeyDigests(prefix: str) → list[Diger]
        Digests of next key set public keys.

    publicKeySetAt(prefix: str, rotationIndex: int) → PublicKeySet | null
        Public key set at a specific rotation index for replay.

    prefixIndex() → int
        Next available prefix index.

    rootAlgorithm() → KeyAlgorithm
        Default root algorithm.

    rootSecurityTier() → SecurityTier
        Default root security tier.
```

---

## 10. KeyVault — Aggregate Root

Central authority for all private key operations. One KeyVault exists per process. It owns the KeyStore, manages AEID authentication, and delegates key creation to strategies.

Cross-ref: `keeping.py:594` (`Manager`)

### 10.1 Construction

```
KeyVault(keyStore: KeyStore, seed: str | null)
```

| Parameter | Description |
|-----------|-------------|
| `keyStore` | Injected KeyStore instance (must be openable) |
| `seed` | qb64 AEID private signing key seed; held in memory only, NEVER persisted |

If the KeyStore is already open, `setup()` is called immediately. Otherwise, setup is deferred until the KeyStore is opened.

### 10.2 Setup

```
setup(aeid: str | null, pidx: int | null, algorithm: KeyAlgorithm | null,
      salt: str | null, tier: SecurityTier | null)
```

Initializes vault-wide globals in the KeyStore on first call. Subsequent calls update only if values have never been initialized (vacuous initialization).

Cross-ref: `keeping.py:688` (`Manager.setup`)

**Behavior:**

1. If KeyStore not open → raise `KeyStoreClosedError`
2. Initialize defaults: `pidx=0`, `algorithm=DETERMINISTIC`, `salt=<random>`, `tier=LOW`
3. If stored `aeid` is empty → call `updateAuthentication(aeid, seed)`
4. If stored `aeid` is not empty → derive SecretEncryptor from AEID, verify seed

### 10.3 Authentication Update

```
updateAuthentication(newAeid: str, seed: str)
```

Changes the AEID. All stored secrets are re-encrypted with the new AEID's key pair.

Cross-ref: `keeping.py:763` (`Manager.updateAeid`)

**Behavior:**

1. If current AEID is set, verify current seed matches current AEID
2. If new AEID is different and non-empty:
   a. Derive new SecretEncryptor from new AEID
   b. Verify new seed matches new AEID
3. Re-encrypt root salt
4. Re-encrypt all per-prefix salts in DerivationParameters
5. Re-encrypt all private keys (decrypt with old, encrypt with new)
6. Store new AEID in KeyStore globals
7. Update in-memory seed and derive new SecretDecryptor

### 10.4 Key Inception

```
inceptKeys(currentCodes: list[str] | null, currentCount: int, currentCode: str,
           nextCodes: list[str] | null, nextCount: int, nextCode: str,
           digestCode: str, algorithm: KeyAlgorithm | null,
           salt: str | null, stem: str | null, tier: SecurityTier | null,
           rooted: bool, transferable: bool, testMode: bool)
    → (verfers: list[Verfer], digers: list[Diger])
```

Creates initial key sets for a new identifier prefix.

Cross-ref: `keeping.py:928` (`Manager.incept`)

**Behavior:**

1. Resolve algorithm/salt/tier from vault root when `rooted=true` and not provided
2. Allocate `pidx` (incremented after use)
3. Create strategy: `KeyGeneratorFactory(algorithm).make(salt, stem, tier)`
4. Generate current signers at `ridx=0, kidx=0`
5. Generate next signers at `ridx=1, kidx=len(current)`
6. Compute digers from next signers
7. Build DerivationParameters and KeySituation
8. Store prefix mapping (first public key → temporary prefix)
9. Store parameters, situation, private keys, public key sets
10. Return `(verfers, digers)`

### 10.5 Key Rotation

```
rotateKeys(prefix: str, nextCodes: list[str] | null, nextCount: int,
           nextCode: str, digestCode: str,
           transferable: bool, testMode: bool, eraseStaleKeys: bool)
    → (verfers: list[Verfer], digers: list[Diger])
```

Advances the three-phase key state for a prefix.

Cross-ref: `keeping.py:1121` (`Manager.rotate`)

**Behavior:**

1. Load DerivationParameters and KeySituation from KeyStore
2. Verify next key set is non-empty (else `NonTransferableError`)
3. Advance: `previous ← current`, `current ← next`
4. Extract verfers from now-current keys (decrypt private keys if AEID set)
5. Decrypt per-prefix salt if AEID set
6. Create strategy from stored parameters
7. Generate new next signers at `ridx = current.ridx + 1`
8. Compute digers
9. Update KeySituation; store new private keys and public key set
10. Erase prior-previous private keys if `eraseStaleKeys=true`
11. Return `(verfers, digers)`

### 10.6 Key Replay

```
replayKeys(prefix: str, digestCode: str, advance: bool, eraseStaleKeys: bool)
    → (verfers: list[Verfer], digers: list[Diger])
```

Replays pre-existing key sequence (from ingested externally-generated keys).

Cross-ref: `keeping.py:1631` (`Manager.replay`)

**Behavior:**

1. Load DerivationParameters and KeySituation
2. If `advance=true`:
   a. Advance three-phase state
   b. Look up next public key set from stored PublicKeySets
   c. If no next set found → raise `IndexError` (end of replay)
3. Extract verfers from current keys
4. Compute digers from next key set
5. Erase stale keys if configured
6. Return `(verfers, digers)`

### 10.7 Signing

```
signSerialization(ser: bytes, pubs: list[str] | null, verfers: list[Verfer] | null,
                  indexed: bool, indices: list[int] | null,
                  ondices: list[int | null] | null)
    → list[Siger] | list[Cigar]
```

Signs serialization using private keys looked up by public keys.

Cross-ref: `keeping.py:1230` (`Manager.sign`)

**Behavior:**

1. Resolve public keys from `pubs` (preferred) or `verfers`
2. For each public key, retrieve private key from KeyStore (decrypt if AEID set)
3. If `indexed=true`:
   a. For each signer at position `j`:
      - `index = indices[j]` if provided, else `j`
      - `ondex = ondices[j]` if provided, else `index`
      - Call `signer.sign(ser, index=index, only=(ondex is null), ondex=ondex)`
   b. Return list of `Siger`
4. If `indexed=false`:
   a. For each signer: call `signer.sign(ser)` (no index)
   b. Return list of `Cigar`

**Validation:**

- If `indices` provided, length MUST match signers count
- If `ondices` provided, length MUST match signers count
- Each index MUST be a non-negative integer
- Each ondex MUST be null or a non-negative integer

### 10.8 Decryption

```
decryptSecret(qb64: str, pubs: list[str] | null, verfers: list[Verfer] | null) → bytes
```

Decrypts an encrypted secret using private keys from the KeyStore.

Cross-ref: `keeping.py:1399` (`Manager.decrypt`)

**Behavior:**

1. Resolve public keys from `pubs` or `verfers`
2. For each public key, retrieve and decrypt private key
3. Convert to X25519 private key
4. Attempt sealed box decryption
5. Return plaintext

### 10.9 External Key Ingestion

```
ingestExternalKeys(secrecies: list[list[str]], initialRotationIndex: int,
                   nextCount: int, nextCode: str, digestCode: str,
                   algorithm: KeyAlgorithm, salt: str | null,
                   stem: str | null, tier: SecurityTier | null,
                   rooted: bool, transferable: bool, testMode: bool)
    → (prefix: str, verferies: list[list[Verfer]])
```

Imports externally-generated key sequences. Used for import, recovery from backup, or migration.

Cross-ref: `keeping.py:1455` (`Manager.ingest`)

**Behavior:**

1. Process each list in `secrecies` as an ordered key set from inception onward
2. Store all private keys (does NOT erase any ingested keys)
3. After all ingested sets, create new next keys using the specified algorithm
4. Build DerivationParameters and KeySituation with `initialRotationIndex` controlling the `previous/current/next` window
5. Return the prefix (from first public key) and all verfer lists

### 10.10 Prefix Move

```
movePrefix(old: str, new: str)
```

Reassigns KeyStore entries from a temporary prefix (first public key) to the actual derived prefix. Must be called after inception when the permanent prefix differs from the first public key.

Cross-ref: `keeping.py:1061` (`Manager.move`)

**Behavior:**

1. Verify old prefix exists; verify new prefix does not exist
2. Move DerivationParameters: copy to new, remove old
3. Move KeySituation: copy to new, remove old
4. Move all PublicKeySet entries from old prefix to new
5. Update prefix mapping: old now points to new; create new self-reference

### 10.11 Stale Key Erasure

```
eraseStaleKeys(prefix: str)
```

Manually erases private keys from the previous key set. Normally called automatically during rotation when `eraseStaleKeys=true`.

### 10.12 Query

```
keyInventory() → KeyInventory
```

Returns a read-only KeyInventory view over the KeyStore.

---

## 11. IdentifierContext — Aggregate Root

IdentifierContext manages a single AID lifecycle, combining a KeyVault reference with BC-1 key state and event construction.

Cross-ref: `habbing.py:2166` (`Hab`)

### 11.1 Factory Methods

```
IdentifierContext.create(name: str, registry: IdentifierRegistry,
                         keyConfig: InceptionKeySetBuilder,
                         eventConfig: InceptionBuilder)
    → IdentifierContext

IdentifierContext.restore(name: str, prefix: str, registry: IdentifierRegistry)
    → IdentifierContext
```

**create:** Combines key inception (via KeyVault) with event inception (via BC-1 InceptionBuilder).

1. Build key set: `keyConfig.build(vault)` → `(verfers, digers)`
2. Configure event builder with verfers, digers, thresholds
3. Build inception event: `eventConfig.build()` → `Event`
4. Move prefix: `vault.movePrefix(firstPubKey, event.prefix)`
5. Process event through local EventProcessor
6. Store habitat record

**restore:** Loads existing identifier from stored records.

### 11.2 Event Construction

```
makeInceptionEvent(...) → SignedEvent
makeRotationEvent(nextCount, nextCodes, digestCode, ...) → SignedEvent
makeInteractionEvent(seals, ...) → SignedEvent
```

Each method:

1. Builds the event using BC-1 builders
2. Signs using `vault.signSerialization(event.raw, pubs=currentKeys)`
3. Returns `SignedEvent` (event + signatures)

Cross-ref: `habbing.py:2209` (`Hab.make`), `habbing.py:1100` (`BaseHab`)

### 11.3 Signing and Decryption

```
sign(ser: bytes) → list[Siger]
decrypt(qb64: str) → bytes
endorse(serder: Serder) → list[Cigar]
```

Delegates to KeyVault operations using this identifier's current key set.

### 11.4 Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | str | Human-readable alias |
| `prefix` | str | qb64 AID prefix |
| `keyState` | IdentifierState | BC-1 key state aggregate |
| `isTransferable` | bool | True if next keys exist |
| `isDelegated` | bool | True if delegator prefix is set |
| `algorithm` | KeyAlgorithm | Key creation algorithm for this identifier |

---

## 12. IdentifierRegistry — Aggregate Root / Factory

IdentifierRegistry manages a multi-AID environment with shared KeyStore, KeyVault, and EventProcessor.

Cross-ref: `habbing.py:111` (`Habery`)

### 12.1 Construction

```
IdentifierRegistry(name: str, keyStore: KeyStore, eventRepository: EventRepository,
                   seed: str | null, salt: str | null, ...)
```

Creates and owns:

- `KeyVault` (from keyStore + seed)
- `EventProcessor` (from eventRepository)
- Internal map of `IdentifierContext` instances keyed by prefix

### 12.2 Factory Methods

```
createIdentifier(name: str, keyConfig: InceptionKeySetBuilder,
                 eventConfig: InceptionBuilder) → IdentifierContext

createGroupIdentifier(name: str, signingMembers: list,
                      rotatingMembers: list, ...) → GroupIdentifierContext

joinGroupIdentifier(name: str, ...) → GroupIdentifierContext
```

### 12.3 Lifecycle

```
setup() → void
    Initializes all shared resources. Opens KeyStore and EventRepository.
    Loads existing identifiers from persistent storage.

loadIdentifiers() → void
    Loads all stored Habitat records and reconstitutes IdentifierContext instances.

deleteIdentifier(prefix: str) → void
    Removes identifier from registry (does not erase keys from KeyStore).
```

### 12.4 Queries

```
identifiers() → dict[str, IdentifierContext]
    All managed identifiers keyed by prefix.

byName(name: str) → IdentifierContext | null
    Lookup identifier by human-readable name.

byPrefix(prefix: str) → IdentifierContext | null
    Lookup identifier by prefix.

localPrefixes() → set[str]
    Set of all locally managed prefix strings.
```

### 12.5 Auxiliary

```
extractGroupKeys(signingMembers: list, rotatingMembers: list)
    → (verfers: list[Verfer], digers: list[Diger])
```

Extracts and concatenates public keys from member key states for group construction.

Cross-ref: `habbing.py:633` (`extractMerfersMigers`)

---

## 13. GroupIdentifierContext — Aggregate Root

GroupIdentifierContext manages a multi-sig identifier where multiple independent participants each hold partial signing authority.

Cross-ref: `habbing.py:2622` (`GroupHab`)

### 13.1 Construction

```
GroupIdentifierContext(signingMemberIds: list, rotatingMemberIds: list | null,
                      localMember: IdentifierContext, ...)
```

| Parameter | Description |
|-----------|-------------|
| `signingMemberIds` | qb64 prefixes of all signing members |
| `rotatingMemberIds` | qb64 prefixes of all rotating members (defaults to signing members) |
| `localMember` | The local participant's IdentifierContext |

Cross-ref: `habbing.py:2667` (`GroupHab.__init__`)

### 13.2 Commands

```
make(signingThreshold, nextThreshold, ...) → SignedEvent
    Creates group inception event. Each participant signs their portion.

sign(serder: Serder) → list[Siger]
    Signs event using local member's keys.

rotate(signingMembers: list | null, rotatingMembers: list | null, ...) → SignedEvent
    Creates group rotation event. Membership may change.

interact(seals: list, ...) → SignedEvent
    Creates group interaction event.
```

### 13.3 Properties

| Property | Type | Description |
|----------|------|-------------|
| `signingMemberIds` | list[str] | qb64 prefixes of signing members |
| `rotatingMemberIds` | list[str] | qb64 prefixes of rotating members |
| `localMember` | IdentifierContext | Local participant's context |
| `signingThreshold` | str or list | Current signing threshold |

---

## 14. Invariant Contract

These invariants MUST hold in any conformant implementation. Each maps to a verifiable runtime check.

| # | Invariant | Enforcement Point | Cross-ref |
|---|-----------|-------------------|-----------|
| 1 | Private keys NEVER persisted in plaintext when AEID is set | KeyStore.putPrivateKey encrypts when encrypter provided | `keeping.py:1046–1047` |
| 2 | Decrypted keys zeroed from memory after use | Consumer responsibility; library provides lifecycle hooks | — |
| 3 | Deterministic derivation: same inputs → same key pair | KeyDeriver.stretch is pure given same salt+path+tier | `signing.py:411–448` |
| 4 | Three-phase rotation: previous←current, current←next, next←new | rotateKeys advances KeySituation atomically | `keeping.py:1168–1170` |
| 5 | Contiguous rotation indices: `next.ridx = current.ridx + 1` | rotateKeys computes `ridx = current.ridx + 1` | `keeping.py:1200` |
| 6 | Contiguous key indices within each KeySet | kidx computed as `next.kidx + len(current.pubs)` | `keeping.py:1201` |
| 7 | AEID authentication required when AEID is set | All decrypt operations check `aeid && !decrypter` → DecryptionError | `keeping.py:1174–1176` |
| 8 | Non-transferable identifiers cannot rotate | rotateKeys checks `nxt.pubs` is non-empty | `keeping.py:1165–1166` |
| 9 | movePrefix must be called after inception | Prefix mapping starts at first public key, must be moved to derived prefix | `keeping.py:1033–1035` |
| 10 | No duplicate prefixes in KeyStore | putPrefixMapping returns false on duplicate | `keeping.py:1034–1035` |
| 11 | Stale key erasure after rotation (configurable) | eraseStaleKeys parameter controls old key removal | `keeping.py:1223–1225` |
| 12 | Seed never persisted to KeyStore | `_seed` is memory-only; no KeyStore method writes it | `keeping.py:613–617` |

---

## 15. Configuration

```
VaultConfig:
    defaultAlgorithm: KeyAlgorithm = DETERMINISTIC
    defaultSecurityTier: SecurityTier = LOW
    defaultDigestCode: str = "Blake3_256"       — MtrDex.Blake3_256
    defaultKeyCode: str = "Ed25519_Seed"        — MtrDex.Ed25519_Seed
    eraseOnRotation: bool = true
    testMode: bool = false
```

Cross-ref: `keeping.py:688–734` (Manager.setup default values)

These defaults are used by InceptionKeySetBuilder when values are not explicitly specified and `rooted=true` is set.

---

## 16. Test Specification

### 16.1 Type and Constant Tests (15 tests)

| # | Test | Section |
|---|------|---------|
| T001 | KeySet default construction has empty pubs, ridx=0, kidx=0, dt="" | §2.1 |
| T002 | KeySet construction with explicit values round-trips all fields | §2.1 |
| T003 | KeySituation default construction has three default KeySets | §2.2 |
| T004 | DerivationParameters default has pidx=0, algo=DETERMINISTIC | §2.3 |
| T005 | DerivationParameters preserves encrypted salt field | §2.3 |
| T006 | PublicKeySet stores and retrieves pubs list | §2.4 |
| T007 | KeyAlgorithm enumeration values match wire strings | §2.5 |
| T008 | SecurityTier.LOW has ops=2, mem=64MiB | §2.6 |
| T009 | SecurityTier.MEDIUM has ops=3, mem=256MiB | §2.6 |
| T010 | SecurityTier.HIGH has ops=4, mem=1GiB | §2.6 |
| T011 | EncryptedSecret with code X25519_Cipher_Salt has correct raw size | §2.7 |
| T012 | EncryptedSecret with code X25519_Cipher_Seed has correct raw size | §2.7 |
| T013 | EncryptedSecret rejects unsupported cipher code | §2.7 |
| T014 | EncryptedSecret round-trips through qb64 serialization | §2.7 |
| T015 | VaultConfig default values match specification | §15 |

### 16.2 Error Hierarchy Tests (10 tests)

| # | Test | Section |
|---|------|---------|
| T016 | KeyStoreClosedError is raised when KeyStore not open | §3 |
| T017 | AuthenticationError is raised when seed mismatches AEID | §3 |
| T018 | DecryptionError extends AuthenticationError | §3 |
| T019 | DecryptionError raised when AEID set but no decrypter | §3 |
| T020 | KeyNotFoundError raised when public key not in store | §3 |
| T021 | NonTransferableError raised on empty next key rotation | §3 |
| T022 | ThresholdError raised on index length mismatch | §3 |
| T023 | DerivationError raised on unsupported code | §3 |
| T024 | DuplicatePrefixError raised on double inception | §3 |
| T025 | PrefixNotFoundError raised on rotating absent prefix | §3 |

### 16.3 KeyDeriver Tests (18 tests)

| # | Test | Section |
|---|------|---------|
| T026 | Default construction generates random 16-byte salt | §5.1 |
| T027 | Construction from explicit raw preserves salt | §5.1 |
| T028 | Construction from qb64 round-trips | §5.1 |
| T029 | Stretch produces deterministic output for same inputs | §5.1 |
| T030 | Stretch with different paths produces different output | §5.1 |
| T031 | Stretch with different tiers produces different output | §5.1 |
| T032 | Stretch with testMode=true uses minimal parameters | §5.1 |
| T033 | Stretch output length matches requested size | §5.1 |
| T034 | Signer produces valid Ed25519 SigningKey | §5.1 |
| T035 | Signer with transferable=true produces transferable Verfer | §5.1 |
| T036 | Signer with transferable=false produces non-transferable Verfer | §5.1 |
| T037 | Signers batch creates correct count with sequential paths | §5.1 |
| T038 | Signers batch with start offset shifts path indices | §5.1 |
| T039 | Path construction: stem + ridx hex + kidx hex | §5.1 |
| T040 | Path with empty stem defaults to pidx hex | §5.1 |
| T041 | Invalid salt size rejected | §5.1 |
| T042 | Unsupported tier raises DerivationError | §5.1 |
| T043 | Deterministic reproduction: same salt+path+tier → same key pair | §5.1 |

### 16.4 Encryption / Decryption Tests (16 tests)

| # | Test | Section |
|---|------|---------|
| T044 | SecretEncryptor construction from Ed25519 verkey | §6.1 |
| T045 | SecretEncryptor rejects non-Ed25519 verkey | §6.1 |
| T046 | Encrypt salt produces X25519_Cipher_Salt cipher | §6.1 |
| T047 | Encrypt seed produces X25519_Cipher_Seed cipher | §6.1 |
| T048 | Encrypt with explicit code overrides auto-detection | §6.1 |
| T049 | verifySeed returns true for matching seed | §6.1 |
| T050 | verifySeed returns false for mismatched seed | §6.1 |
| T051 | SecretDecryptor construction from seed | §6.2 |
| T052 | SecretDecryptor rejects non-Ed25519 seed | §6.2 |
| T053 | Decrypt salt cipher returns KeyDeriver | §6.2 |
| T054 | Decrypt seed cipher returns SigningKey | §6.2 |
| T055 | Decrypt with bare=true returns raw bytes | §6.2 |
| T056 | Decrypt with explicit klas overrides auto-detection | §6.2 |
| T057 | Round-trip: encrypt(salt) → decrypt → original salt | §6.1, §6.2 |
| T058 | Round-trip: encrypt(seed) → decrypt → original seed | §6.1, §6.2 |
| T059 | Decrypt with wrong key fails | §6.2 |

### 16.5 Key Generation Strategy Tests (14 tests)

| # | Test | Section |
|---|------|---------|
| T060 | RandomKeyGenerator creates correct count of signers | §7.2 |
| T061 | RandomKeyGenerator each signer has unique raw material | §7.2 |
| T062 | RandomKeyGenerator respects transferable flag | §7.2 |
| T063 | RandomKeyGenerator with explicit codes uses each code | §7.2 |
| T064 | DeterministicKeyGenerator creates correct count of signers | §7.3 |
| T065 | DeterministicKeyGenerator same inputs → same signers | §7.3 |
| T066 | DeterministicKeyGenerator different pidx → different signers | §7.3 |
| T067 | DeterministicKeyGenerator different ridx → different signers | §7.3 |
| T068 | DeterministicKeyGenerator respects stem override | §7.3 |
| T069 | DeterministicKeyGenerator respects tier | §7.3 |
| T070 | DeterministicKeyGenerator path: stem + ridx hex + kidx hex | §7.3 |
| T071 | KeyGeneratorFactory RANDOM → RandomKeyGenerator | §7.4 |
| T072 | KeyGeneratorFactory DETERMINISTIC → DeterministicKeyGenerator | §7.4 |
| T073 | KeyGeneratorFactory unsupported algorithm raises error | §7.4 |

### 16.6 Builder Tests (18 tests)

| # | Test | Section |
|---|------|---------|
| T074 | InceptionKeySetBuilder default: 1 current key, 1 next key | §8.1 |
| T075 | InceptionKeySetBuilder custom counts | §8.1 |
| T076 | InceptionKeySetBuilder explicit codes override count | §8.1 |
| T077 | InceptionKeySetBuilder rooted inherits vault defaults | §8.1 |
| T078 | InceptionKeySetBuilder non-rooted uses provided values | §8.1 |
| T079 | InceptionKeySetBuilder non-transferable: ncount=0 produces empty digers | §8.1 |
| T080 | InceptionKeySetBuilder rejects zero current count | §8.1 |
| T081 | InceptionKeySetBuilder rejects negative next count | §8.1 |
| T082 | InceptionKeySetBuilder stores DerivationParameters in KeyStore | §8.1 |
| T083 | InceptionKeySetBuilder increments pidx | §8.1 |
| T084 | RotationKeySetBuilder advances three-phase state | §8.2 |
| T085 | RotationKeySetBuilder rejects absent prefix | §8.2 |
| T086 | RotationKeySetBuilder rejects non-transferable prefix | §8.2 |
| T087 | RotationKeySetBuilder eraseStaleKeys removes old private keys | §8.2 |
| T088 | RotationKeySetBuilder eraseStaleKeys=false preserves old keys | §8.2 |
| T089 | GroupKeySetBuilder assembles verfers from member key states | §8.3 |
| T090 | GroupKeySetBuilder assembles digers from rotating members | §8.3 |
| T091 | GroupKeySetBuilder validates threshold against key count | §8.3 |

### 16.7 KeyVault Tests (35 tests)

| # | Test | Section |
|---|------|---------|
| T092 | Construction with open KeyStore calls setup | §10.1 |
| T093 | Construction with closed KeyStore defers setup | §10.1 |
| T094 | Setup initializes globals on first call | §10.2 |
| T095 | Setup does not overwrite existing globals | §10.2 |
| T096 | Setup raises KeyStoreClosedError when store closed | §10.2 |
| T097 | Setup with AEID derives encrypter/decrypter | §10.2 |
| T098 | Setup with AEID but wrong seed raises AuthenticationError | §10.2 |
| T099 | updateAuthentication changes AEID and re-encrypts all secrets | §10.3 |
| T100 | updateAuthentication with empty AEID unencrypts all secrets | §10.3 |
| T101 | updateAuthentication verifies old seed before re-encryption | §10.3 |
| T102 | inceptKeys returns correct verfers and digers | §10.4 |
| T103 | inceptKeys stores private keys in KeyStore | §10.4 |
| T104 | inceptKeys increments pidx | §10.4 |
| T105 | inceptKeys with AEID encrypts stored keys | §10.4 |
| T106 | inceptKeys rejects duplicate prefix | §10.4 |
| T107 | inceptKeys with rooted=true uses vault salt | §10.4 |
| T108 | inceptKeys with rooted=false uses provided salt | §10.4 |
| T109 | rotateKeys advances three-phase state correctly | §10.5 |
| T110 | rotateKeys returns correct verfers from prior next | §10.5 |
| T111 | rotateKeys generates new next keys | §10.5 |
| T112 | rotateKeys erases stale keys when configured | §10.5 |
| T113 | rotateKeys preserves stale keys when erase=false | §10.5 |
| T114 | rotateKeys rejects non-transferable prefix | §10.5 |
| T115 | rotateKeys with AEID decrypts keys | §10.5 |
| T116 | replayKeys returns correct verfers at current index | §10.6 |
| T117 | replayKeys advances state when advance=true | §10.6 |
| T118 | replayKeys raises IndexError at end of sequence | §10.6 |
| T119 | signSerialization produces indexed Sigers | §10.7 |
| T120 | signSerialization produces unindexed Cigars | §10.7 |
| T121 | signSerialization with custom indices | §10.7 |
| T122 | signSerialization with custom ondices | §10.7 |
| T123 | signSerialization raises on index length mismatch | §10.7 |
| T124 | decryptSecret round-trips through encrypt/decrypt | §10.8 |
| T125 | movePrefix transfers all KeyStore entries | §10.10 |
| T126 | movePrefix rejects non-existent old prefix | §10.10 |

### 16.8 IdentifierContext Tests (25 tests)

| # | Test | Section |
|---|------|---------|
| T127 | create produces inception event with correct prefix | §11.1 |
| T128 | create stores habitat record | §11.1 |
| T129 | create calls movePrefix | §11.1 |
| T130 | restore loads existing identifier | §11.1 |
| T131 | makeInceptionEvent returns signed event | §11.2 |
| T132 | makeRotationEvent advances key state | §11.2 |
| T133 | makeInteractionEvent preserves sequence continuity | §11.2 |
| T134 | sign delegates to vault with current keys | §11.3 |
| T135 | decrypt delegates to vault | §11.3 |
| T136 | endorse produces Cigar list | §11.3 |
| T137 | name property returns alias | §11.4 |
| T138 | prefix property returns qb64 prefix | §11.4 |
| T139 | keyState returns BC-1 IdentifierState | §11.4 |
| T140 | isTransferable true when next keys exist | §11.4 |
| T141 | isTransferable false when next keys empty | §11.4 |
| T142 | isDelegated true when delegator set | §11.4 |
| T143 | isDelegated false when no delegator | §11.4 |
| T144 | algorithm returns identifier's key algorithm | §11.4 |
| T145 | create with non-transferable produces correct event | §11.1 |
| T146 | create with delegator produces delegated inception | §11.1 |
| T147 | rotation updates BC-1 key state | §11.2 |
| T148 | interaction does not change key state | §11.2 |
| T149 | sign with AEID vault succeeds when seed provided | §11.3 |
| T150 | sign with AEID vault fails without seed | §11.3 |
| T151 | restore fails for unknown prefix | §11.1 |

### 16.9 IdentifierRegistry Tests (20 tests)

| # | Test | Section |
|---|------|---------|
| T152 | Construction initializes shared resources | §12.1 |
| T153 | setup opens KeyStore and EventRepository | §12.3 |
| T154 | loadIdentifiers reconstitutes all stored contexts | §12.3 |
| T155 | createIdentifier returns new IdentifierContext | §12.2 |
| T156 | createIdentifier stores in registry map | §12.2 |
| T157 | createGroupIdentifier returns GroupIdentifierContext | §12.2 |
| T158 | joinGroupIdentifier joins existing group | §12.2 |
| T159 | deleteIdentifier removes from registry | §12.3 |
| T160 | identifiers returns all managed contexts | §12.4 |
| T161 | byName lookup returns correct context | §12.4 |
| T162 | byName returns null for unknown name | §12.4 |
| T163 | byPrefix lookup returns correct context | §12.4 |
| T164 | byPrefix returns null for unknown prefix | §12.4 |
| T165 | localPrefixes returns all managed prefixes | §12.4 |
| T166 | extractGroupKeys concatenates member verfers | §12.5 |
| T167 | extractGroupKeys concatenates member digers | §12.5 |
| T168 | Multiple identifiers share same KeyVault | §12.1 |
| T169 | Multiple identifiers share same EventProcessor | §12.1 |
| T170 | Registry close closes KeyStore and EventRepository | §12.3 |
| T171 | Registry with AEID passes seed to KeyVault | §12.1 |

### 16.10 GroupIdentifierContext Tests (15 tests)

| # | Test | Section |
|---|------|---------|
| T172 | Construction stores signing and rotating member IDs | §13.1 |
| T173 | make creates group inception with assembled keys | §13.2 |
| T174 | sign produces partial signatures from local member | §13.2 |
| T175 | rotate changes group membership | §13.2 |
| T176 | interact creates interaction event | §13.2 |
| T177 | signingMemberIds property returns member list | §13.3 |
| T178 | rotatingMemberIds defaults to signing members | §13.3 |
| T179 | localMember returns local participant context | §13.3 |
| T180 | Group with weighted threshold validates correctly | §13.2 |
| T181 | Group rotation with member change updates member lists | §13.2 |
| T182 | Group rotation stores updated member IDs in KeyStore | §13.2 |
| T183 | Group inception event has correct combined key list | §13.2 |
| T184 | Group with single member degenerates to simple case | §13.2 |
| T185 | Group sign uses local member's key index | §13.2 |
| T186 | Group with mixed algorithms assembles keys correctly | §13.2 |

### 16.11 KeyStore Compliance Tests (20 tests)

| # | Test | Section |
|---|------|---------|
| T187 | open/close lifecycle | §4.2 |
| T188 | Operations on closed store raise KeyStoreClosedError | §4.2 |
| T189 | putGlobal/getGlobal round-trip | §4.2 |
| T190 | pinGlobal overwrites existing value | §4.2 |
| T191 | putPrivateKey/getPrivateKey round-trip (unencrypted) | §4.2 |
| T192 | putPrivateKey/getPrivateKey round-trip (encrypted) | §4.2 |
| T193 | removePrivateKey deletes entry | §4.2 |
| T194 | getPrivateKey returns null for missing key | §4.2 |
| T195 | putPrefixMapping/getPrefixMapping round-trip | §4.2 |
| T196 | putPrefixMapping returns false on duplicate | §4.2 |
| T197 | putDerivationParameters/getDerivationParameters round-trip | §4.2 |
| T198 | putKeySituation/getKeySituation round-trip | §4.2 |
| T199 | putPublicKeySet/getPublicKeySet round-trip | §4.2 |
| T200 | putSigningMembers/getSigningMembers round-trip | §4.2 |
| T201 | putRotatingMembers/getRotatingMembers round-trip | §4.2 |
| T202 | pinPrivateKey overwrites existing | §4.2 |
| T203 | removeDerivationParameters deletes entry | §4.2 |
| T204 | pinDerivationParameters upserts | §4.2 |
| T205 | pinKeySituation upserts | §4.2 |
| T206 | Multiple concurrent prefixes isolated | §4.2 |

### 16.12 Invariant Tests (15 tests)

| # | Test | Section |
|---|------|---------|
| T207 | INV-1: Private keys encrypted in store when AEID set | §14 |
| T208 | INV-3: Deterministic derivation reproducibility | §14 |
| T209 | INV-4: Three-phase rotation advances correctly | §14 |
| T210 | INV-5: Rotation index contiguous after rotation | §14 |
| T211 | INV-6: Key index contiguous within key set | §14 |
| T212 | INV-7: Operations fail without decrypter when AEID set | §14 |
| T213 | INV-8: Non-transferable rotation rejected | §14 |
| T214 | INV-9: movePrefix required after inception | §14 |
| T215 | INV-10: Duplicate prefix rejected | §14 |
| T216 | INV-11: Stale keys erased after rotation | §14 |
| T217 | INV-12: Seed not present in KeyStore after setup | §14 |
| T218 | INV-4: Multiple rotations maintain three-phase chain | §14 |
| T219 | INV-5: ridx monotonically increases | §14 |
| T220 | INV-6: kidx = sum of prior key set sizes | §14 |
| T221 | INV-7: AEID change re-encrypts all secrets | §14 |

### 16.13 Integration / Lifecycle Tests (22 tests)

| # | Test | Section |
|---|------|---------|
| T222 | Full lifecycle: incept → rotate → sign → decrypt | §10, §11 |
| T223 | Full lifecycle with AEID: setup → incept → rotate → sign | §10 |
| T224 | AEID vault: change AEID mid-lifecycle | §10.3 |
| T225 | AEID vault: remove AEID (unencrypt) | §10.3 |
| T226 | Multiple prefixes: two identifiers share vault | §10, §12 |
| T227 | Multiple prefixes: rotation of one does not affect other | §10, §12 |
| T228 | Non-transferable: incept with ncount=0, rotation rejected | §10.4, §10.5 |
| T229 | Group lifecycle: create group → sign → rotate group | §12, §13 |
| T230 | External key ingestion: import → replay → sign | §10.9, §10.6 |
| T231 | External key ingestion: replay advances through all sets | §10.9, §10.6 |
| T232 | External key ingestion: replay raises at end | §10.6 |
| T233 | Deterministic recovery: same salt recreates same keys | §5, §10 |
| T234 | IdentifierContext create + IdentifierRegistry lookup | §11, §12 |
| T235 | IdentifierContext rotation updates registry state | §11, §12 |
| T236 | GroupIdentifierContext partial signing coordination | §13 |
| T237 | KeyVault with InMemoryKeyStore (testing adapter) | §10 |
| T238 | Registry setup with pre-existing data loads correctly | §12.3 |
| T239 | Multiple rotations: 5 successive rotations maintain invariants | §10.5, §14 |
| T240 | Concurrent inception: two prefixes created back-to-back | §10.4 |
| T241 | KeyInventory reflects state after rotation | §9, §10.5 |
| T242 | Interaction event after rotation uses new keys | §11.2 |
| T243 | Registry deleteIdentifier followed by createIdentifier with same name | §12.3 |

### Test Summary

| Category | Count |
|----------|-------|
| Type/Constant Tests | 15 |
| Error Hierarchy Tests | 10 |
| KeyDeriver Tests | 18 |
| Encryption/Decryption Tests | 16 |
| Key Generation Strategy Tests | 14 |
| Builder Tests | 18 |
| KeyVault Tests | 35 |
| IdentifierContext Tests | 25 |
| IdentifierRegistry Tests | 20 |
| GroupIdentifierContext Tests | 15 |
| KeyStore Compliance Tests | 20 |
| Invariant Tests | 15 |
| Integration/Lifecycle Tests | 22 |
| **Total** | **243** |

---

## Appendix A: Usage Examples

### A.1 Basic Lifecycle (Deterministic Keys)

```
// 1. Open key store and create vault
keyStore = InMemoryKeyStore()
keyStore.open()
vault = KeyVault(keyStore=keyStore)
vault.setup(algorithm=DETERMINISTIC, tier=LOW)

// 2. Incept: creates first signing keys and pre-committed next keys
(verfers, digers) = vault.inceptKeys(
    currentCount=1,
    nextCount=1,
    transferable=true,
    rooted=true
)
// verfers[0].qb64 is the temporary prefix (first public key)
// digers[0].qb64 is the Blake3-256 digest of the next public key

// 3. Build inception event using BC-1 builder (not shown in detail)
// prefix = derivePrefix(inceptionEvent)

// 4. Move to permanent prefix
vault.movePrefix(old=verfers[0].qb64, new=prefix)

// 5. Sign a serialization
sigers = vault.signSerialization(
    ser=eventBytes,
    pubs=[verfers[0].qb64],
    indexed=true
)

// 6. Rotate keys
(newVerfers, newDigers) = vault.rotateKeys(
    prefix=prefix,
    nextCount=1,
    eraseStaleKeys=true
)

// 7. Sign with rotated keys
sigers = vault.signSerialization(
    ser=rotationEventBytes,
    pubs=[newVerfers[0].qb64],
    indexed=true
)
```

### A.2 AEID-Protected Vault

```
// Generate AEID key pair
aeidSigner = SigningKey(transferable=false)  // non-transferable
aeid = aeidSigner.verfer.qb64               // public key as AEID
seed = aeidSigner.qb64                      // private seed

// Setup vault with AEID authentication
vault = KeyVault(keyStore=keyStore, seed=seed)
vault.setup(aeid=aeid, algorithm=DETERMINISTIC, tier=MEDIUM)
// All subsequent private key storage is encrypted with AEID

// Incept (keys stored encrypted)
(verfers, digers) = vault.inceptKeys(currentCount=2, nextCount=2)

// Change AEID (re-encrypts all secrets)
newAeidSigner = SigningKey(transferable=false)
vault.updateAuthentication(newAeid=newAeidSigner.verfer.qb64, seed=newAeidSigner.qb64)
```

### A.3 Group Multi-Sig

```
// Each participant creates their own identifier
alice = registry.createIdentifier(name="alice", ...)
bob = registry.createIdentifier(name="bob", ...)

// Create group with both as signing members
group = registry.createGroupIdentifier(
    name="joint-account",
    signingMembers=[
        (alice.prefix, alice.keyState.sequenceNumber),
        (bob.prefix, bob.keyState.sequenceNumber)
    ],
    signingThreshold="2"  // both must sign
)

// Alice signs her part
aliceSigers = group.sign(inceptionEvent)

// Bob signs his part (on his machine)
bobSigers = group.sign(inceptionEvent)

// Combine signatures and process
```

---

## Appendix B: DDD Name Mapping

| keripy Name | DDD Domain Name | DDD Pattern | Source File:Line |
|---|---|---|---|
| Manager | **KeyVault** | Aggregate Root | keeping.py:594 |
| Keeper | **KeyStore** | Repository Interface | keeping.py:133 |
| Hab | **IdentifierContext** | Aggregate Root | habbing.py:2166 |
| Habery | **IdentifierRegistry** | Aggregate Root / Factory | habbing.py:111 |
| GroupHab | **GroupIdentifierContext** | Aggregate Root | habbing.py:2622 |
| Salter | **KeyDeriver** | Domain Service | signing.py:329 |
| Signer | **SigningKey** | CESR Shared Kernel | signing.py:33 |
| Encrypter | **SecretEncryptor** | Domain Service | signing.py:750 |
| Decrypter | **SecretDecryptor** | Domain Service | signing.py:885 |
| Cipher | **EncryptedSecret** | Value Object | signing.py:655 |
| Creator | **KeyGenerationStrategy** | Strategy Interface | keeping.py:357 |
| RandyCreator | **RandomKeyGenerator** | Strategy | keeping.py:408 |
| SaltyCreator | **DeterministicKeyGenerator** | Strategy | keeping.py:452 |
| Creatory | **KeyGeneratorFactory** | Factory | keeping.py:536 |
| PubLot | **KeySet** | Value Object | keeping.py:42 |
| PreSit | **KeySituation** | Value Object | keeping.py:66 |
| PrePrm | **DerivationParameters** | Value Object | keeping.py:79 |
| PubSet | **PublicKeySet** | Value Object | keeping.py:94 |
| Algos | **KeyAlgorithm** | Enumeration | keeping.py:38 |
| Tiers | **SecurityTier** | Enumeration | signing.py:28 |

---

## Appendix C: Wire-Format Field Reference

### C.1 KeyStore Global Parameters

Stored in the `gbls` sub-database with string keys.

| Key | Type | Description |
|-----|------|-------------|
| `"aeid"` | str | qb64 non-transferable prefix for authentication/encryption; empty means unprotected |
| `"pidx"` | str | Hex-encoded next prefix index |
| `"algo"` | str | Default root algorithm (`"randy"` or `"salty"`) |
| `"salt"` | str | qb64 root salt; may be encrypted if AEID is set |
| `"tier"` | str | Default root security tier (`"low"`, `"med"`, `"high"`) |

### C.2 KeyStore Sub-Database Layout

| Sub-DB | Key | Value | DDD Type |
|--------|-----|-------|----------|
| `gbls.` | parameter label (str) | parameter value (str) | Vault globals |
| `pris.` | public key (qb64 bytes) | private key (qb64, optionally encrypted) | SigningKey |
| `prxs.` | public key (qb64 bytes) | encrypted proxy cipher | EncryptedSecret |
| `nxts.` | public key (qb64 bytes) | encrypted next-key cipher | EncryptedSecret |
| `pres.` | first public key (qb64 bytes) | prefix (Prefixer qb64) | Prefix mapping |
| `prms.` | prefix (qb64 bytes) | serialized DerivationParameters | DerivationParameters |
| `sits.` | prefix (qb64 bytes) | serialized KeySituation | KeySituation |
| `pubs.` | prefix.rotationIndex (bytes) | serialized PublicKeySet | PublicKeySet |
| `smids.` | prefix (qb64 bytes) | list of (Prefixer, Number) tuples | Signing member IDs |
| `rmids.` | prefix (qb64 bytes) | list of (Prefixer, Number) tuples | Rotating member IDs |

### C.3 Compound Key Construction

The `pubs` sub-database uses a compound key combining prefix and rotation index:

```
key = prefix_bytes + b"." + rotation_index_as_32_char_hex
```

Cross-ref: `keeping.py:105` (`riKey` function)

---

## Module Structure

```
key_management/
    types                    — KeySet, KeySituation, DerivationParameters,
                               PublicKeySet, KeyAlgorithm, SecurityTier,
                               EncryptedSecret, AuthenticationIdentifier
    errors                   — error hierarchy (10 types)
    config                   — VaultConfig
    ports/
        cryptographic_suite  — CryptographicSuite (port interface)
        key_store            — KeyStore (repository interface)
    derivation/
        key_deriver          — KeyDeriver (deterministic from salt)
        strategy             — KeyGenerationStrategy, RandomKeyGenerator,
                               DeterministicKeyGenerator, KeyGeneratorFactory
    encryption/
        secret_encryptor     — SecretEncryptor
        secret_decryptor     — SecretDecryptor
    builders/
        inception_keys       — InceptionKeySetBuilder
        rotation_keys        — RotationKeySetBuilder
        group_keys           — GroupKeySetBuilder
    views/
        key_inventory        — KeyInventory (read-only)
    key_vault                — KeyVault aggregate root
    identifier_context       — IdentifierContext aggregate root
    identifier_registry      — IdentifierRegistry aggregate root / factory
    group_context            — GroupIdentifierContext aggregate root
    memory/
        in_memory_key_store  — InMemoryKeyStore (for testing)
```

**Dependency rules:**

- `types`, `errors`, `config` have **zero** internal dependencies beyond each other
- `ports/` defines abstract interfaces only — no concrete implementations
- `derivation/` depends on `types`, `ports/cryptographic_suite`, and CESR shared kernel
- `encryption/` depends on `types`, `ports/cryptographic_suite`, and CESR shared kernel
- `builders/` depends on `types`, `key_vault` (for build execution)
- `views/` depends on `types`, `ports/key_store`
- `key_vault` depends on `types`, `errors`, `ports/`, `derivation/`, `encryption/`
- `identifier_context` depends on `key_vault` and BC-1 (`IdentifierState`, `EventProcessor`, builders)
- `identifier_registry` depends on `identifier_context`, `key_vault`, `ports/key_store`
- `group_context` depends on `identifier_context`, `key_vault`
- `memory/` implements `ports/key_store` — used for testing only
- **No circular dependencies** exist in this module graph
