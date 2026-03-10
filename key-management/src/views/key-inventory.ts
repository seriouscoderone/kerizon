/**
 * KeyInventory — read-only query interface over the KeyStore.
 *
 * Cross-ref: keeping.py:594–643 (Manager properties)
 */
import type { IKeyStore } from "../ports/key-store.js";
import type { ICryptographicSuite } from "../ports/cryptographic-suite.js";
import {
  type KeySituation,
  type DerivationParameters,
  type PublicKeySet,
  KeyAlgorithm,
  SecurityTier,
} from "../types.js";
import {
  type Diger,
  makeDiger,
  matterDecode,
} from "../cesr-helpers.js";
import { PrefixNotFoundError } from "../errors.js";
import { InMemoryKeyStore } from "../memory/in-memory-key-store.js";
import { blake3 } from "@noble/hashes/blake3";

export class KeyInventory {
  private readonly store: IKeyStore;
  private readonly crypto: ICryptographicSuite;

  constructor(store: IKeyStore, crypto: ICryptographicSuite) {
    this.store = store;
    this.crypto = crypto;
  }

  /** All prefix strings managed by this vault. */
  identifiers(): string[] {
    const inMemStore = this.store as InMemoryKeyStore;
    if (inMemStore.allPrefixes) {
      return inMemStore.allPrefixes();
    }
    return [];
  }

  /** Three-phase key state for a prefix. */
  keySituation(prefix: string): KeySituation {
    const s = this.store.getKeySituation(prefix);
    if (!s) throw new PrefixNotFoundError(`Prefix not found: ${prefix}`);
    return s;
  }

  /** Derivation parameters for a prefix. */
  derivationParameters(prefix: string): DerivationParameters {
    const p = this.store.getDerivationParameters(prefix);
    if (!p) throw new PrefixNotFoundError(`Prefix not found: ${prefix}`);
    return p;
  }

  /** True if prefix exists in KeyStore. */
  isManaged(prefix: string): boolean {
    return this.store.getDerivationParameters(prefix) !== null;
  }

  /** Public keys from current key set. */
  currentSigningKeys(prefix: string): string[] {
    const s = this.keySituation(prefix);
    return s.current.pubs;
  }

  /** Digests of next key set public keys. */
  nextKeyDigests(prefix: string): Diger[] {
    const s = this.keySituation(prefix);
    return s.next.pubs.map((qb64) => {
      const digest = blake3(new TextEncoder().encode(qb64));
      return makeDiger(digest);
    });
  }

  /** Public key set at a specific rotation index for replay. */
  publicKeySetAt(prefix: string, rotationIndex: number): PublicKeySet | null {
    const key = `${prefix}.${rotationIndex.toString(16).padStart(32, "0")}`;
    return this.store.getPublicKeySet(key);
  }

  /** Next available prefix index. */
  prefixIndex(): number {
    const val = this.store.getGlobal("pidx");
    return val ? parseInt(val, 10) : 0;
  }

  /** Default root algorithm. */
  rootAlgorithm(): KeyAlgorithm {
    return (this.store.getGlobal("algo") as KeyAlgorithm) ?? KeyAlgorithm.DETERMINISTIC;
  }

  /** Default root security tier. */
  rootSecurityTier(): SecurityTier {
    return (this.store.getGlobal("tier") as SecurityTier) ?? SecurityTier.LOW;
  }
}
