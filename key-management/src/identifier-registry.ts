/**
 * IdentifierRegistry — aggregate root / factory for multi-AID environment.
 *
 * Cross-ref: habbing.py:111 (Habery)
 */
import {
  EventProcessor,
  InMemoryEventRepository,
  DefaultCryptoProvider,
  DomainEventBus,
  type EventRepository,
} from "kel-event-processing";
import type { Threshold } from "kel-event-processing";
import { KeyVault } from "./key-vault.js";
import { IdentifierContext } from "./identifier-context.js";
import { GroupIdentifierContext } from "./group-context.js";
import type { IKeyStore } from "./ports/key-store.js";
import type { InceptionKeySetBuilder } from "./builders/inception-keys.js";
import { IdentifierNotFoundError } from "./errors.js";
import type { ICryptographicSuite } from "./ports/cryptographic-suite.js";
import { DefaultCryptographicSuite } from "./adapters/default-crypto-suite.js";
import type { Verfer, Diger } from "./cesr-helpers.js";
import { matterDecode, MtrDex } from "./cesr-helpers.js";
import { blake3 } from "@noble/hashes/blake3";
import { makeDiger } from "./cesr-helpers.js";

export class IdentifierRegistry {
  readonly name: string;
  private readonly _vault: KeyVault;
  private readonly _processor: EventProcessor;
  private readonly _keyStore: IKeyStore;
  private readonly _eventRepo: EventRepository;
  private readonly _bus: DomainEventBus;
  private readonly _identifiers = new Map<string, IdentifierContext>();
  private readonly _groupIdentifiers = new Map<string, GroupIdentifierContext>();

  constructor(opts: {
    name: string;
    keyStore: IKeyStore;
    eventRepository?: EventRepository;
    seed?: string | null;
    salt?: string | null;
    cryptoSuite?: ICryptographicSuite;
  }) {
    this.name = opts.name;
    this._keyStore = opts.keyStore;
    this._eventRepo = opts.eventRepository ?? new InMemoryEventRepository();
    const cryptoSuite = opts.cryptoSuite ?? new DefaultCryptographicSuite();
    this._vault = new KeyVault(this._keyStore, opts.seed ?? null, cryptoSuite);
    this._bus = new DomainEventBus();
    this._processor = new EventProcessor(this._eventRepo, this._bus, new DefaultCryptoProvider());
  }

  /**
   * Initialize all shared resources. Opens KeyStore and EventRepository.
   */
  setup(): void {
    if (!this._keyStore.isOpened()) {
      this._keyStore.open();
    }
    this._vault.setup();
  }

  /**
   * Create a new identifier.
   */
  async createIdentifier(
    name: string,
    keyConfig: InceptionKeySetBuilder,
    signingThreshold?: Threshold,
    nextThreshold?: Threshold,
    witnesses?: string[],
    toad?: number,
  ): Promise<IdentifierContext> {
    const ctx = await IdentifierContext.create(
      name,
      this._vault,
      this._processor,
      keyConfig,
      this._bus,
      signingThreshold,
      nextThreshold,
      witnesses,
      toad,
    );
    this._identifiers.set(ctx.prefix, ctx);
    return ctx;
  }

  /**
   * Create a group multi-sig identifier.
   */
  createGroupIdentifier(
    name: string,
    localMember: IdentifierContext,
    signingMemberIds: string[],
    rotatingMemberIds?: string[],
  ): GroupIdentifierContext {
    const group = new GroupIdentifierContext({
      signingMemberIds,
      rotatingMemberIds,
      localMember,
      vault: this._vault,
      processor: this._processor,
    });
    return group;
  }

  /**
   * Join an existing group identifier.
   */
  joinGroupIdentifier(
    name: string,
    prefix: string,
    localMember: IdentifierContext,
    signingMemberIds: string[],
    rotatingMemberIds?: string[],
  ): GroupIdentifierContext {
    const group = new GroupIdentifierContext({
      signingMemberIds,
      rotatingMemberIds,
      localMember,
      vault: this._vault,
      processor: this._processor,
    });
    this._groupIdentifiers.set(prefix, group);
    return group;
  }

  /**
   * Remove identifier from registry (does not erase keys).
   */
  deleteIdentifier(prefix: string): void {
    this._identifiers.delete(prefix);
    this._groupIdentifiers.delete(prefix);
  }

  /**
   * Close all shared resources.
   */
  close(): void {
    if (this._keyStore.isOpened()) {
      this._keyStore.close();
    }
  }

  // ── Queries ─────────────────────────────────────────────────────────

  /** All managed identifiers keyed by prefix. */
  identifiers(): Map<string, IdentifierContext> {
    return new Map(this._identifiers);
  }

  /** Lookup identifier by human-readable name. */
  byName(name: string): IdentifierContext | null {
    for (const ctx of this._identifiers.values()) {
      if (ctx.name === name) return ctx;
    }
    return null;
  }

  /** Lookup identifier by prefix. */
  byPrefix(prefix: string): IdentifierContext | null {
    return this._identifiers.get(prefix) ?? null;
  }

  /** Set of all locally managed prefix strings. */
  localPrefixes(): Set<string> {
    return new Set(this._identifiers.keys());
  }

  /**
   * Extract and concatenate public keys from member key states for group construction.
   */
  extractGroupKeys(
    signingMembers: Array<{ prefix: string; sequenceNumber: number }>,
    rotatingMembers: Array<{ prefix: string; sequenceNumber: number }>,
  ): { verfers: Verfer[]; digers: Diger[] } {
    const verfers: Verfer[] = [];
    const digers: Diger[] = [];

    for (const member of signingMembers) {
      const ctx = this._identifiers.get(member.prefix);
      if (!ctx) continue;
      const state = ctx.keyState;
      for (const keyQb64 of state.signingKeys) {
        const raw = matterDecode(keyQb64);
        const code = keyQb64[0];
        verfers.push({
          raw,
          code,
          qb64: keyQb64,
          qb64b: new TextEncoder().encode(keyQb64),
          transferable: code !== MtrDex.Ed25519N,
        });
      }
    }

    const rotMems = rotatingMembers.length > 0 ? rotatingMembers : signingMembers;
    for (const member of rotMems) {
      const ctx = this._identifiers.get(member.prefix);
      if (!ctx) continue;
      const state = ctx.keyState;
      for (const digestQb64 of state.nextKeyDigests) {
        const raw = matterDecode(digestQb64);
        digers.push({
          raw,
          code: digestQb64[0],
          qb64: digestQb64,
          qb64b: new TextEncoder().encode(digestQb64),
        });
      }
    }

    return { verfers, digers };
  }

  // ── Shared resources ─────────────────────────────────────────────────

  get vault(): KeyVault { return this._vault; }
  get processor(): EventProcessor { return this._processor; }
  get eventRepository(): EventRepository { return this._eventRepo; }
  get keyStore(): IKeyStore { return this._keyStore; }
}
