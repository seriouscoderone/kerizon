/**
 * KeyVault — aggregate root for all private key operations.
 *
 * Cross-ref: keeping.py:594 (Manager)
 */
import { blake3 } from "@noble/hashes/blake3";
import {
  MtrDex,
  matterEncode,
  matterDecode,
  makeVerfer,
  makeDiger,
  type Verfer,
  type Diger,
  encryptedSecretFromQb64,
  makeEncryptedSecretFromRaw,
} from "./cesr-helpers.js";
import {
  KeyAlgorithm,
  SecurityTier,
  type KeySet,
  type KeySituation,
  type DerivationParameters,
  type PublicKeySet,
  type EncryptedSecret,
  makeKeySet,
  makeKeySituation,
  makeDerivationParameters,
} from "./types.js";
import {
  KeyStoreClosedError,
  AuthenticationError,
  DecryptionError,
  KeyNotFoundError,
  NonTransferableError,
  ThresholdError,
  DuplicatePrefixError,
  PrefixNotFoundError,
  DerivationError,
} from "./errors.js";
import type { IKeyStore } from "./ports/key-store.js";
import type { ICryptographicSuite } from "./ports/cryptographic-suite.js";
import { makeSigningKey, type SigningKey } from "./signing-key.js";
import { KeyDeriver } from "./derivation/key-deriver.js";
import { SecretEncryptor } from "./encryption/secret-encryptor.js";
import { SecretDecryptor } from "./encryption/secret-decryptor.js";
import { KeyGeneratorFactory } from "./derivation/strategy.js";
import { KeyInventory } from "./views/key-inventory.js";
import { InMemoryKeyStore } from "./memory/in-memory-key-store.js";
import { DefaultCryptographicSuite } from "./adapters/default-crypto-suite.js";

/** Compound key for public key sets: prefix + "." + ridx hex (32 chars). */
function pubSetKey(prefix: string, ridx: number): string {
  return `${prefix}.${ridx.toString(16).padStart(32, "0")}`;
}

export class KeyVault {
  private readonly store: IKeyStore;
  private readonly cryptoSuite: ICryptographicSuite;
  /** In-memory AEID seed (never persisted) */
  private _seed: string | null = null;
  private _encrypter: SecretEncryptor | null = null;
  private _decrypter: SecretDecryptor | null = null;

  constructor(
    keyStore: IKeyStore,
    seed?: string | null,
    cryptoSuite?: ICryptographicSuite,
  ) {
    this.store = keyStore;
    this.cryptoSuite = cryptoSuite ?? new DefaultCryptographicSuite();
    if (seed) this._seed = seed;

    if (this.store.isOpened()) {
      this.setup();
    }
  }

  /** Open the store and run setup. */
  open(): void {
    if (!this.store.isOpened()) {
      this.store.open();
    }
    this.setup();
  }

  /**
   * Initialize vault-wide globals on first call.
   *
   * Cross-ref: keeping.py:688 (Manager.setup)
   */
  setup(
    aeid?: string | null,
    pidx?: number | null,
    algorithm?: KeyAlgorithm | null,
    salt?: string | null,
    tier?: SecurityTier | null,
  ): void {
    if (!this.store.isOpened()) {
      throw new KeyStoreClosedError("KeyStore must be open before setup");
    }

    // Initialize defaults if not already set
    if (this.store.getGlobal("pidx") === null) {
      this.store.putGlobal("pidx", pidx != null ? String(pidx) : "0");
    }
    if (this.store.getGlobal("algo") === null) {
      this.store.putGlobal("algo", algorithm ?? KeyAlgorithm.DETERMINISTIC);
    }
    if (this.store.getGlobal("tier") === null) {
      this.store.putGlobal("tier", tier ?? SecurityTier.LOW);
    }
    if (this.store.getGlobal("salt") === null) {
      // Generate a random root salt
      const rootSalt = this.cryptoSuite.generateRandom(16);
      const saltQb64 = matterEncode(rootSalt, MtrDex.Salt_128);
      this.store.putGlobal("salt", salt ?? saltQb64);
    }

    const storedAeid = this.store.getGlobal("aeid");

    if (!storedAeid) {
      // First-time AEID setup
      if (aeid || this._seed) {
        this.updateAuthentication(aeid ?? "", this._seed ?? "");
      } else {
        this.store.putGlobal("aeid", "");
      }
    } else if (storedAeid && this._seed) {
      // AEID already set — verify the provided seed
      if (storedAeid !== "") {
        this._encrypter = new SecretEncryptor({ verkey: storedAeid, crypto: this.cryptoSuite });
        if (!this._encrypter.verifySeed(this._seed)) {
          throw new AuthenticationError(
            "Provided seed does not match stored AEID",
          );
        }
        this._decrypter = new SecretDecryptor({
          seed: this._seed,
          crypto: this.cryptoSuite,
        });
      }
    }
  }

  /**
   * Change the AEID, re-encrypting all secrets.
   *
   * Cross-ref: keeping.py:763 (Manager.updateAeid)
   */
  updateAuthentication(newAeid: string, seed: string): void {
    if (!this.store.isOpened()) {
      throw new KeyStoreClosedError();
    }

    const currentAeid = this.store.getGlobal("aeid") ?? "";
    const oldEncrypter = this._encrypter;
    const oldDecrypter = this._decrypter;

    // Verify current seed if AEID is set
    if (currentAeid && oldEncrypter && seed !== this._seed) {
      if (this._seed && !oldEncrypter.verifySeed(this._seed)) {
        throw new AuthenticationError("Current seed does not match current AEID");
      }
    }

    let newEncrypter: SecretEncryptor | null = null;
    let newDecrypter: SecretDecryptor | null = null;

    if (newAeid && newAeid !== "") {
      newEncrypter = new SecretEncryptor({ verkey: newAeid, crypto: this.cryptoSuite });
      if (seed && !newEncrypter.verifySeed(seed)) {
        throw new AuthenticationError("New seed does not match new AEID");
      }
      if (seed) {
        newDecrypter = new SecretDecryptor({ seed, crypto: this.cryptoSuite });
      }
    }

    // Re-encrypt root salt
    this._reencryptRootSalt(oldDecrypter, newEncrypter);

    // Re-encrypt per-prefix salts and private keys
    this._reencryptAllSecrets(oldDecrypter, newEncrypter);

    // Update stored AEID
    this.store.pinGlobal("aeid", newAeid);

    // Update in-memory state
    this._seed = seed || null;
    this._encrypter = newEncrypter;
    this._decrypter = newDecrypter;
  }

  private _reencryptRootSalt(
    oldDecrypter: SecretDecryptor | null,
    newEncrypter: SecretEncryptor | null,
  ): void {
    const saltVal = this.store.getGlobal("salt");
    if (!saltVal) return;

    let saltQb64: string;
    if (saltVal.startsWith("1AAH")) {
      // Currently encrypted salt
      if (!oldDecrypter) return; // can't decrypt without decrypter
      const cipher = encryptedSecretFromQb64(saltVal);
      const deriver = oldDecrypter.decrypt(cipher, undefined, "salt", true, false) as KeyDeriver;
      saltQb64 = deriver.qb64;
    } else {
      saltQb64 = saltVal;
    }

    if (newEncrypter) {
      // Encrypt salt with new encrypter
      const deriver = new KeyDeriver({ qb64: saltQb64, crypto: this.cryptoSuite });
      const cipher = newEncrypter.encrypt(undefined, {
        raw: deriver.raw,
        qb64: deriver.qb64,
        code: MtrDex.Salt_128,
      });
      this.store.pinGlobal("salt", cipher.qb64);
    } else {
      // Store as plaintext
      this.store.pinGlobal("salt", saltQb64);
    }
  }

  private _reencryptAllSecrets(
    oldDecrypter: SecretDecryptor | null,
    newEncrypter: SecretEncryptor | null,
  ): void {
    const inMemStore = this.store as InMemoryKeyStore;
    if (!inMemStore.allPrivateKeyPublicKeys) return;

    // Re-encrypt per-prefix salts in DerivationParameters
    for (const prefix of inMemStore.allPrefixes()) {
      const params = this.store.getDerivationParameters(prefix);
      if (!params || !params.salt) continue;

      let saltQb64: string;
      if (params.salt.startsWith("1AAH")) {
        if (!oldDecrypter) continue;
        const cipher = encryptedSecretFromQb64(params.salt);
        const deriver = oldDecrypter.decrypt(cipher, undefined, "salt", true, false) as KeyDeriver;
        saltQb64 = deriver.qb64;
      } else {
        saltQb64 = params.salt;
      }

      if (newEncrypter && saltQb64) {
        const deriver = new KeyDeriver({ qb64: saltQb64, crypto: this.cryptoSuite });
        const cipher = newEncrypter.encrypt(undefined, {
          raw: deriver.raw,
          qb64: deriver.qb64,
          code: MtrDex.Salt_128,
        });
        params.salt = cipher.qb64;
      } else {
        params.salt = saltQb64;
      }
      this.store.pinDerivationParameters(prefix, params);
    }

    // Re-encrypt private keys
    for (const pubKey of inMemStore.allPrivateKeyPublicKeys()) {
      const stored = inMemStore.getRawStoredKey(pubKey);
      if (!stored) continue;

      let signer: SigningKey;
      if (stored.encrypted) {
        if (!oldDecrypter) continue;
        const cipher = encryptedSecretFromQb64(stored.cipherQb64!);
        signer = oldDecrypter.decrypt(cipher, undefined, "seed", stored.transferable ?? true, false) as SigningKey;
      } else {
        const raw = matterDecode(stored.seedQb64!);
        signer = makeSigningKey(raw, stored.transferable ?? true);
      }

      if (newEncrypter) {
        const cipher = newEncrypter.encrypt(undefined, {
          raw: signer.raw,
          qb64: signer.qb64,
          code: signer.code,
        });
        inMemStore.storeRawKey(pubKey, {
          cipherQb64: cipher.qb64,
          encrypted: true,
          transferable: signer.transferable,
        });
      } else {
        inMemStore.storeRawKey(pubKey, {
          seedQb64: signer.qb64,
          encrypted: false,
          transferable: signer.transferable,
        });
      }
    }
  }

  /**
   * Create initial key sets for a new identifier.
   *
   * Cross-ref: keeping.py:928 (Manager.incept)
   */
  inceptKeys(opts: {
    currentCodes?: string[] | null;
    currentCount?: number;
    currentCode?: string | undefined;
    nextCodes?: string[] | null;
    nextCount?: number;
    nextCode?: string | undefined;
    digestCode?: string | undefined;
    algorithm?: KeyAlgorithm | null;
    salt?: string | null;
    stem?: string | null;
    tier?: SecurityTier | null;
    rooted?: boolean;
    transferable?: boolean;
    testMode?: boolean;
  }): { verfers: Verfer[]; digers: Diger[] } {
    if (!this.store.isOpened()) throw new KeyStoreClosedError();

    const {
      currentCodes = null,
      currentCount = 1,
      currentCode = MtrDex.Ed25519_Seed,
      nextCodes = null,
      nextCount = 1,
      nextCode = MtrDex.Ed25519_Seed,
      digestCode = MtrDex.Blake3_256,
      rooted = true,
      transferable = true,
      testMode = false,
    } = opts;

    // Validate
    const resolvedCurrentCount = currentCodes ? currentCodes.length : currentCount;
    if (resolvedCurrentCount <= 0) {
      throw new DerivationError("currentCount must be > 0");
    }
    const resolvedNextCount = nextCodes ? nextCodes.length : nextCount;
    if (resolvedNextCount < 0) {
      throw new DerivationError("nextCount must be >= 0");
    }

    // Resolve algorithm, salt, tier from root when rooted
    let algorithm = opts.algorithm ?? null;
    let salt = opts.salt ?? null;
    let tier = opts.tier ?? null;

    if (rooted) {
      if (!algorithm) {
        algorithm = (this.store.getGlobal("algo") as KeyAlgorithm) ?? KeyAlgorithm.DETERMINISTIC;
      }
      if (!salt) {
        const rootSalt = this.store.getGlobal("salt");
        if (rootSalt) {
          // Decrypt if encrypted
          salt = this._decryptSalt(rootSalt);
        }
      }
      if (!tier) {
        tier = (this.store.getGlobal("tier") as SecurityTier) ?? SecurityTier.LOW;
      }
    }

    algorithm = algorithm ?? KeyAlgorithm.DETERMINISTIC;

    // Allocate pidx
    const pidxStr = this.store.getGlobal("pidx") ?? "0";
    const pidx = parseInt(pidxStr, 10);
    this.store.pinGlobal("pidx", String(pidx + 1));

    // Create strategy
    const strategy = new KeyGeneratorFactory(algorithm).make(
      salt,
      opts.stem ?? null,
      tier,
      this.cryptoSuite,
    );

    // Generate current signers at ridx=0, kidx=0
    const currentSigners = strategy.create(
      currentCodes,
      currentCount,
      currentCode,
      pidx,
      0, // ridx
      0, // kidx
      transferable,
      testMode,
    );

    // Generate next signers at ridx=1, kidx=len(current)
    const nextSigners =
      resolvedNextCount > 0
        ? strategy.create(
            nextCodes,
            resolvedNextCount,
            nextCode,
            pidx,
            1, // ridx
            currentSigners.length, // kidx
            transferable,
            testMode,
          )
        : [];

    // Build verfers
    const verfers = currentSigners.map((s) => s.verfer);

    // Compute digers from next signers
    const digers = nextSigners.map((s) => {
      const verferBytes = s.verfer.qb64b;
      const digest = blake3(verferBytes);
      return makeDiger(digest, digestCode);
    });

    // Build key sets
    const now = new Date().toISOString();
    const currentKeySet = makeKeySet({
      pubs: currentSigners.map((s) => s.verfer.qb64),
      ridx: 0,
      kidx: 0,
      dt: now,
    });
    const nextKeySet = makeKeySet({
      pubs: nextSigners.map((s) => s.verfer.qb64),
      ridx: 1,
      kidx: currentSigners.length,
      dt: now,
    });

    const situation = makeKeySituation({
      previous: makeKeySet(),
      current: currentKeySet,
      next: nextKeySet,
    });

    // The first public key acts as the initial prefix key
    const firstPubKey = verfers[0].qb64;

    // Check for duplicate
    if (this.store.getDerivationParameters(firstPubKey)) {
      throw new DuplicatePrefixError(`Prefix already exists: ${firstPubKey}`);
    }

    // Store derivation parameters
    const effectiveSalt = strategy.salt || salt || "";
    // Encrypt salt if AEID is set
    const storedSalt = this._encryptSaltForStorage(effectiveSalt);
    const params = makeDerivationParameters({
      pidx,
      algorithm,
      salt: storedSalt,
      stem: opts.stem ?? strategy.stem,
      tier: (tier ?? strategy.tier) || SecurityTier.LOW,
    });

    this.store.putDerivationParameters(firstPubKey, params);
    this.store.putKeySituation(firstPubKey, situation);
    this.store.putPrefixMapping(firstPubKey, firstPubKey);

    // Store current private keys
    for (const signer of currentSigners) {
      this.store.putPrivateKey(signer.verfer.qb64, signer, this._encrypter);
    }

    // Store next private keys
    for (const signer of nextSigners) {
      this.store.putPrivateKey(signer.verfer.qb64, signer, this._encrypter);
    }

    // Store public key sets
    this.store.putPublicKeySet(pubSetKey(firstPubKey, 0), {
      pubs: currentKeySet.pubs,
    });
    if (nextKeySet.pubs.length > 0) {
      this.store.putPublicKeySet(pubSetKey(firstPubKey, 1), {
        pubs: nextKeySet.pubs,
      });
    }

    return { verfers, digers };
  }

  /**
   * Advance the three-phase key state for a prefix.
   *
   * Cross-ref: keeping.py:1121 (Manager.rotate)
   */
  rotateKeys(opts: {
    prefix: string;
    nextCodes?: string[] | null;
    nextCount?: number;
    nextCode?: string;
    digestCode?: string;
    transferable?: boolean;
    testMode?: boolean;
    eraseStaleKeys?: boolean;
  }): { verfers: Verfer[]; digers: Diger[] } {
    if (!this.store.isOpened()) throw new KeyStoreClosedError();

    const {
      prefix,
      nextCodes = null,
      nextCount = 1,
      nextCode = MtrDex.Ed25519_Seed,
      digestCode = MtrDex.Blake3_256,
      transferable = true,
      testMode = false,
      eraseStaleKeys = true,
    } = opts;

    const params = this.store.getDerivationParameters(prefix);
    if (!params) throw new PrefixNotFoundError(`Prefix not found: ${prefix}`);

    const situation = this.store.getKeySituation(prefix);
    if (!situation) throw new PrefixNotFoundError(`Key situation not found: ${prefix}`);

    // Check non-transferable
    if (situation.next.pubs.length === 0) {
      throw new NonTransferableError(`Prefix is non-transferable: ${prefix}`);
    }

    const previousPrevKeys = situation.previous;

    // Advance: previous ← current, current ← next
    const newPrevious = situation.current;
    const newCurrent = situation.next;

    // Get current verfers (from now-current keys)
    const verfers = newCurrent.pubs.map((qb64) => {
      const code = qb64[0] === MtrDex.Ed25519N ? MtrDex.Ed25519N : MtrDex.Ed25519;
      const raw = matterDecode(qb64);
      return makeVerfer(raw, code === MtrDex.Ed25519);
    });

    // Decrypt per-prefix salt if needed
    const storedSalt = params.salt;
    const salt = storedSalt ? this._decryptSalt(storedSalt) : null;

    // Create strategy
    const strategy = new KeyGeneratorFactory(params.algorithm).make(
      salt,
      params.stem || null,
      params.tier as SecurityTier,
      this.cryptoSuite,
    );

    // Generate new next signers
    const resolvedNextCount = nextCodes ? nextCodes.length : nextCount;
    const newNextSigners =
      resolvedNextCount > 0
        ? strategy.create(
            nextCodes,
            resolvedNextCount,
            nextCode,
            params.pidx,
            newCurrent.ridx + 1,
            newCurrent.kidx + newCurrent.pubs.length,
            transferable,
            testMode,
          )
        : [];

    // Compute new digers
    const digers = newNextSigners.map((s) => {
      const verferBytes = s.verfer.qb64b;
      const digest = blake3(verferBytes);
      return makeDiger(digest, digestCode);
    });

    // Build new next key set
    const now = new Date().toISOString();
    const newNextKeySet = makeKeySet({
      pubs: newNextSigners.map((s) => s.verfer.qb64),
      ridx: newCurrent.ridx + 1,
      kidx: newCurrent.kidx + newCurrent.pubs.length,
      dt: now,
    });

    // Update situation
    const newSituation = makeKeySituation({
      previous: newPrevious,
      current: { ...newCurrent },
      next: newNextKeySet,
    });
    this.store.pinKeySituation(prefix, newSituation);

    // Store new private keys
    for (const signer of newNextSigners) {
      this.store.putPrivateKey(signer.verfer.qb64, signer, this._encrypter);
    }

    // Store new public key set
    if (newNextKeySet.pubs.length > 0) {
      const pkKey = pubSetKey(prefix, newNextKeySet.ridx);
      this.store.putPublicKeySet(pkKey, { pubs: newNextKeySet.pubs });
    }

    // Erase stale keys from previous-previous
    if (eraseStaleKeys && previousPrevKeys.pubs.length > 0) {
      for (const pub of previousPrevKeys.pubs) {
        this.store.removePrivateKey(pub);
      }
    }

    return { verfers, digers };
  }

  /**
   * Replay pre-existing key sequence.
   *
   * Cross-ref: keeping.py:1631 (Manager.replay)
   */
  replayKeys(opts: {
    prefix: string;
    digestCode?: string;
    advance?: boolean;
    eraseStaleKeys?: boolean;
  }): { verfers: Verfer[]; digers: Diger[] } {
    if (!this.store.isOpened()) throw new KeyStoreClosedError();

    const { prefix, digestCode = MtrDex.Blake3_256, advance = false, eraseStaleKeys = true } = opts;

    const params = this.store.getDerivationParameters(prefix);
    if (!params) throw new PrefixNotFoundError(`Prefix not found: ${prefix}`);

    let situation = this.store.getKeySituation(prefix);
    if (!situation) throw new PrefixNotFoundError(`Key situation not found: ${prefix}`);

    if (advance) {
      const previousPrev = situation.previous;

      // Advance three-phase state
      const newPrevious = situation.current;
      const nextPubSet = this.store.getPublicKeySet(
        pubSetKey(prefix, situation.next.ridx + 1),
      );
      if (!nextPubSet) {
        throw new RangeError(`No next public key set at ridx ${situation.next.ridx + 1}`);
      }

      const newCurrent = situation.next;
      const newNext = makeKeySet({
        pubs: nextPubSet.pubs,
        ridx: situation.next.ridx + 1,
        kidx: newCurrent.kidx + newCurrent.pubs.length,
        dt: new Date().toISOString(),
      });

      situation = makeKeySituation({ previous: newPrevious, current: newCurrent, next: newNext });
      this.store.pinKeySituation(prefix, situation);

      if (eraseStaleKeys && previousPrev.pubs.length > 0) {
        for (const pub of previousPrev.pubs) {
          this.store.removePrivateKey(pub);
        }
      }
    }

    const verfers = situation.current.pubs.map((qb64) => {
      const code = qb64[0];
      const raw = matterDecode(qb64);
      return makeVerfer(raw, code === MtrDex.Ed25519);
    });

    const digers = situation.next.pubs.map((qb64) => {
      const raw = matterDecode(qb64);
      const digest = blake3(new TextEncoder().encode(qb64));
      return makeDiger(digest, digestCode);
    });

    return { verfers, digers };
  }

  /**
   * Sign serialization using private keys.
   *
   * Cross-ref: keeping.py:1230 (Manager.sign)
   */
  signSerialization(opts: {
    ser: Uint8Array;
    pubs?: string[] | null;
    verfers?: Verfer[] | null;
    indexed?: boolean;
    indices?: number[] | null;
    ondices?: (number | null)[] | null;
  }): Array<import("./cesr-helpers.js").IndexedSig | import("./cesr-helpers.js").UnindexedSig> {
    if (!this.store.isOpened()) throw new KeyStoreClosedError();

    const { ser, indexed = true, indices = null, ondices = null } = opts;
    const pubs = opts.pubs ?? opts.verfers?.map((v) => v.qb64) ?? [];

    if (pubs.length === 0) {
      throw new ThresholdError("No public keys provided for signing");
    }
    if (indices && indices.length !== pubs.length) {
      throw new ThresholdError(
        `indices length (${indices.length}) must match pubs length (${pubs.length})`,
      );
    }
    if (ondices && ondices.length !== pubs.length) {
      throw new ThresholdError(
        `ondices length (${ondices.length}) must match pubs length (${pubs.length})`,
      );
    }

    const sigs: Array<import("./cesr-helpers.js").IndexedSig | import("./cesr-helpers.js").UnindexedSig> = [];

    for (let j = 0; j < pubs.length; j++) {
      const pub = pubs[j];
      const signer = this.store.getPrivateKey(pub, this._decrypter);
      if (!signer) {
        throw new KeyNotFoundError(`Private key not found for: ${pub}`);
      }

      const index = indices ? indices[j] : j;
      const ondex = ondices ? ondices[j] : null;

      sigs.push(signer.sign(ser, indexed, index, ondex));
    }

    return sigs;
  }

  /**
   * Decrypt an encrypted secret using private keys.
   *
   * Cross-ref: keeping.py:1399 (Manager.decrypt)
   */
  decryptSecret(opts: {
    qb64: string;
    pubs?: string[] | null;
    verfers?: Verfer[] | null;
  }): Uint8Array {
    if (!this.store.isOpened()) throw new KeyStoreClosedError();

    const pubs = opts.pubs ?? opts.verfers?.map((v) => v.qb64) ?? [];
    if (pubs.length === 0) {
      throw new KeyNotFoundError("No public keys provided for decryption");
    }

    for (const pub of pubs) {
      const signer = this.store.getPrivateKey(pub, this._decrypter);
      if (!signer) continue;

      // Derive X25519 private key from seed
      const { publicKey } = this.cryptoSuite.deriveEdKeyPair(signer.raw);
      const sigKey = new Uint8Array(64);
      sigKey.set(signer.raw);
      sigKey.set(publicKey, 32);
      const x25519Priv = this.cryptoSuite.edPrivateToX25519(sigKey);
      const x25519Pub = this.cryptoSuite.x25519Base(x25519Priv);

      const cipher = encryptedSecretFromQb64(opts.qb64);
      const plaintext = this.cryptoSuite.sealedBoxDecrypt(cipher.raw, x25519Pub, x25519Priv);
      if (plaintext) return plaintext;
    }

    throw new KeyNotFoundError("Unable to decrypt: no matching private key found");
  }

  /**
   * Import externally-generated key sequences.
   *
   * Cross-ref: keeping.py:1455 (Manager.ingest)
   */
  ingestExternalKeys(opts: {
    secrecies: string[][];
    initialRotationIndex?: number;
    nextCount?: number;
    nextCode?: string;
    digestCode?: string;
    algorithm?: KeyAlgorithm;
    salt?: string | null;
    stem?: string | null;
    tier?: SecurityTier | null;
    rooted?: boolean;
    transferable?: boolean;
    testMode?: boolean;
  }): { prefix: string; verferies: Verfer[][] } {
    if (!this.store.isOpened()) throw new KeyStoreClosedError();

    const {
      secrecies,
      initialRotationIndex = 0,
      nextCount = 1,
      nextCode = MtrDex.Ed25519_Seed,
      digestCode = MtrDex.Blake3_256,
      algorithm = KeyAlgorithm.DETERMINISTIC,
      salt = null,
      stem = null,
      tier = null,
      rooted = true,
      transferable = true,
      testMode = false,
    } = opts;

    if (secrecies.length === 0) {
      throw new DerivationError("secrecies must not be empty");
    }

    // Store all ingested keys and collect verfer lists
    const verferies: Verfer[][] = [];
    const allSigners: SigningKey[][] = [];

    for (let ridx = 0; ridx < secrecies.length; ridx++) {
      const seedQb64List = secrecies[ridx];
      const signers = seedQb64List.map((qb64) => {
        const raw = matterDecode(qb64);
        return makeSigningKey(raw, transferable);
      });
      allSigners.push(signers);
      verferies.push(signers.map((s) => s.verfer));
    }

    // Store private keys (no erasure for ingested keys)
    for (const signers of allSigners) {
      for (const signer of signers) {
        const pubKey = signer.verfer.qb64;
        if (!this.store.getDerivationParameters(pubKey)) {
          this.store.putPrivateKey(pubKey, signer, this._encrypter);
        }
      }
    }

    // The first public key of the first key set
    const firstPubKey = allSigners[0][0].verfer.qb64;

    // Allocate pidx
    const pidxStr = this.store.getGlobal("pidx") ?? "0";
    const pidx = parseInt(pidxStr, 10);
    this.store.pinGlobal("pidx", String(pidx + 1));

    // Generate new next signers using strategy
    const resolvedSalt = rooted ? (this._decryptSalt(this.store.getGlobal("salt") ?? "") ?? salt) : salt;
    const strategy = new KeyGeneratorFactory(algorithm).make(
      resolvedSalt,
      stem,
      tier,
      this.cryptoSuite,
    );

    const lastRidx = secrecies.length - 1;
    const lastSigners = allSigners[lastRidx];

    const nextSigners = strategy.create(
      null,
      nextCount,
      nextCode,
      pidx,
      lastRidx + 1,
      lastSigners.length,
      transferable,
      testMode,
    );

    for (const signer of nextSigners) {
      this.store.putPrivateKey(signer.verfer.qb64, signer, this._encrypter);
    }

    // Determine the three-phase window based on initialRotationIndex
    const totalSets = secrecies.length;
    let prevIdx = Math.max(0, initialRotationIndex - 1);
    let currIdx = Math.min(initialRotationIndex, totalSets - 1);

    const prevKeySet = makeKeySet({
      pubs: prevIdx < totalSets ? allSigners[prevIdx].map((s) => s.verfer.qb64) : [],
      ridx: prevIdx,
      kidx: 0,
      dt: new Date().toISOString(),
    });
    const currKeySet = makeKeySet({
      pubs: allSigners[currIdx].map((s) => s.verfer.qb64),
      ridx: currIdx,
      kidx: allSigners.slice(0, currIdx).reduce((sum, arr) => sum + arr.length, 0),
      dt: new Date().toISOString(),
    });
    const nextKeySet = makeKeySet({
      pubs: nextSigners.map((s) => s.verfer.qb64),
      ridx: lastRidx + 1,
      kidx: lastSigners.length,
      dt: new Date().toISOString(),
    });

    const situation = makeKeySituation({
      previous: prevKeySet,
      current: currKeySet,
      next: nextKeySet,
    });

    const params = makeDerivationParameters({
      pidx,
      algorithm,
      salt: strategy.salt || "",
      stem: strategy.stem,
      tier: strategy.tier || SecurityTier.LOW,
    });

    this.store.putDerivationParameters(firstPubKey, params);
    this.store.putKeySituation(firstPubKey, situation);
    this.store.putPrefixMapping(firstPubKey, firstPubKey);

    // Store all public key sets
    for (let i = 0; i < allSigners.length; i++) {
      this.store.putPublicKeySet(pubSetKey(firstPubKey, i), {
        pubs: allSigners[i].map((s) => s.verfer.qb64),
      });
    }
    this.store.putPublicKeySet(pubSetKey(firstPubKey, lastRidx + 1), {
      pubs: nextKeySet.pubs,
    });

    return { prefix: firstPubKey, verferies };
  }

  /**
   * Move prefix entries from old key to new prefix.
   *
   * Cross-ref: keeping.py:1061 (Manager.move)
   */
  movePrefix(oldPrefix: string, newPrefix: string): void {
    if (!this.store.isOpened()) throw new KeyStoreClosedError();

    if (oldPrefix === newPrefix) return;

    const params = this.store.getDerivationParameters(oldPrefix);
    if (!params) throw new PrefixNotFoundError(`Old prefix not found: ${oldPrefix}`);

    if (this.store.getDerivationParameters(newPrefix)) {
      throw new DuplicatePrefixError(`New prefix already exists: ${newPrefix}`);
    }

    // Move DerivationParameters
    this.store.putDerivationParameters(newPrefix, params);
    this.store.removeDerivationParameters(oldPrefix);

    // Move KeySituation
    const situation = this.store.getKeySituation(oldPrefix);
    if (situation) {
      this.store.putKeySituation(newPrefix, situation);
      // Remove old (since putKeySituation checks for existing)
      this.store.pinKeySituation(oldPrefix, makeKeySituation());
      this.store.removeDerivationParameters(oldPrefix); // already done above
    }

    // Move all PublicKeySets from old prefix to new prefix
    // Scan known ridx values from key situation
    if (situation) {
      const ridxValues = [0, 1, 2, 3, 4, 5]; // scan a range
      for (const ridx of ridxValues) {
        const oldKey = pubSetKey(oldPrefix, ridx);
        const pubSet = this.store.getPublicKeySet(oldKey);
        if (pubSet) {
          this.store.putPublicKeySet(pubSetKey(newPrefix, ridx), pubSet);
        }
      }
    }

    // Update prefix mapping: old → new, new → self
    this.store.pinPrefixMapping(oldPrefix, newPrefix);
    this.store.putPrefixMapping(newPrefix, newPrefix);
  }

  /**
   * Erase private keys from the previous key set.
   */
  eraseStaleKeys(prefix: string): void {
    if (!this.store.isOpened()) throw new KeyStoreClosedError();
    const situation = this.store.getKeySituation(prefix);
    if (!situation) return;
    for (const pub of situation.previous.pubs) {
      this.store.removePrivateKey(pub);
    }
  }

  /** Returns a read-only KeyInventory view. */
  keyInventory(): KeyInventory {
    return new KeyInventory(this.store, this.cryptoSuite);
  }

  /** Get the current pidx. */
  get pidx(): number {
    const val = this.store.getGlobal("pidx");
    return val ? parseInt(val, 10) : 0;
  }

  /** Get root algorithm. */
  get rootAlgorithm(): KeyAlgorithm {
    return (this.store.getGlobal("algo") as KeyAlgorithm) ?? KeyAlgorithm.DETERMINISTIC;
  }

  /** Get root security tier. */
  get rootSecurityTier(): SecurityTier {
    return (this.store.getGlobal("tier") as SecurityTier) ?? SecurityTier.LOW;
  }

  /** Returns whether AEID is configured. */
  get hasAeid(): boolean {
    const aeid = this.store.getGlobal("aeid");
    return !!aeid && aeid !== "";
  }

  /** Returns current encrypter (if set). */
  get encrypter(): SecretEncryptor | null {
    return this._encrypter;
  }

  /** Returns current decrypter (if set). */
  get decrypter(): SecretDecryptor | null {
    return this._decrypter;
  }

  /** Returns the key store. */
  get keyStore(): IKeyStore {
    return this.store;
  }

  /** Returns the crypto suite. */
  get crypto(): ICryptographicSuite {
    return this.cryptoSuite;
  }

  // ── Private helpers ────────────────────────────────────────────────

  private _decryptSalt(saltValue: string): string | null {
    if (!saltValue) return null;
    if (saltValue.startsWith("1AAH") && this._decrypter) {
      try {
        const cipher = encryptedSecretFromQb64(saltValue);
        const deriver = this._decrypter.decrypt(cipher, undefined, "salt", true, false) as KeyDeriver;
        return deriver.qb64;
      } catch {
        return null;
      }
    }
    return saltValue;
  }

  private _encryptSaltForStorage(saltQb64: string): string {
    if (!saltQb64) return "";
    if (this._encrypter) {
      const saltRaw = matterDecode(saltQb64);
      if (saltRaw.length !== 16) return saltQb64;
      const deriverTemp = new KeyDeriver({ qb64: saltQb64, crypto: this.cryptoSuite });
      const cipher = this._encrypter.encrypt(undefined, {
        raw: deriverTemp.raw,
        qb64: deriverTemp.qb64,
        code: MtrDex.Salt_128,
      });
      return cipher.qb64;
    }
    return saltQb64;
  }
}
