/**
 * IdentifierContext — aggregate root managing a single AID lifecycle.
 *
 * Cross-ref: habbing.py:2166 (Hab)
 */
import {
  IdentifierState,
  EventProcessor,
  InceptionBuilder,
  RotationBuilder,
  InteractionBuilder,
  type Signer,
  type SignedEvent,
  signEvent,
  type AnySeal,
  type Threshold,
  DomainEventBus,
} from "kel-event-processing";
import type { HashFn } from "cesr-ts";
import { blake3 } from "@noble/hashes/blake3";
import {
  type Verfer,
  type Diger,
  type IndexedSig,
  type UnindexedSig,
  matterDecode,
} from "./cesr-helpers.js";
import { KeyAlgorithm } from "./types.js";
import type { KeyVault } from "./key-vault.js";
import type { InceptionKeySetBuilder } from "./builders/inception-keys.js";
import { IdentifierNotFoundError, KeyNotFoundError } from "./errors.js";

/** Hash function based on blake3 (sync). */
const defaultHashFn: HashFn = (data: Uint8Array): Uint8Array => blake3(data);

/** Helper to create a Signer from our IndexedSig for BC-1's signEvent. */
function makeSignerFromKey(
  signingKey: import("./signing-key.js").SigningKey,
  index: number,
  ondex?: number,
): Signer {
  return {
    index,
    ondex,
    sign: async (message: Uint8Array) => {
      const sig = signingKey.sign(message, true, index, ondex ?? null) as IndexedSig;
      return sig.raw;
    },
  };
}

export class IdentifierContext {
  readonly name: string;
  readonly prefix: string;
  private readonly _vault: KeyVault;
  private readonly _processor: EventProcessor;

  private constructor(
    name: string,
    prefix: string,
    vault: KeyVault,
    processor: EventProcessor,
  ) {
    this.name = name;
    this.prefix = prefix;
    this._vault = vault;
    this._processor = processor;
  }

  /**
   * Create a new identifier: build key set, build inception event, process it.
   */
  static async create(
    name: string,
    vault: KeyVault,
    processor: EventProcessor,
    keyConfig: InceptionKeySetBuilder,
    bus: DomainEventBus,
    signingThreshold?: Threshold,
    nextThreshold?: Threshold,
    witnesses?: string[],
    toad?: number,
    configTraits?: string[],
  ): Promise<IdentifierContext> {
    // Build key set
    const { verfers, digers } = keyConfig.build(vault);

    // Build inception event using blake3 as HashFn
    const thresh = signingThreshold ?? "1";
    const nThresh = nextThreshold ?? (digers.length > 0 ? "1" : "0");

    const inceptionBuilder = new InceptionBuilder(defaultHashFn)
      .signingKeys(verfers.map((v) => v.qb64))
      .signingThreshold(thresh)
      .nextKeys(digers.map((d) => d.qb64))
      .nextKeyThreshold(nThresh);

    if (witnesses && witnesses.length > 0) {
      inceptionBuilder.witnesses(witnesses);
    }
    if (toad !== undefined) {
      inceptionBuilder.witnessThreshold(toad);
    }

    const builtEvent = inceptionBuilder.build();
    const prefix = builtEvent.prefix;
    const firstPubKey = verfers[0].qb64;

    // Retrieve private signing keys to create Signer objects
    const signers: Signer[] = [];
    for (let j = 0; j < verfers.length; j++) {
      const pubKey = verfers[j].qb64;
      // Get private key from vault store (using firstPubKey as the temp prefix mapping)
      const sk = vault.keyStore.getPrivateKey(pubKey, vault.decrypter);
      if (sk) {
        signers.push(makeSignerFromKey(sk, j));
      }
    }

    const signedEvent = await signEvent(builtEvent, signers);

    // Move prefix from first public key to actual derived prefix
    if (firstPubKey !== prefix) {
      vault.movePrefix(firstPubKey, prefix);
    }

    // Process event through EventProcessor
    await processor.ingestEvent(
      { raw: builtEvent.raw, fields: builtEvent.fields },
      signedEvent.sigers,
      { local: true },
    );

    // Store habitat record
    vault.keyStore.putGlobal(`hab:${name}`, JSON.stringify({ name, prefix }));

    return new IdentifierContext(name, prefix, vault, processor);
  }

  /**
   * Restore an existing identifier.
   */
  static restore(
    name: string,
    prefix: string,
    vault: KeyVault,
    processor: EventProcessor,
  ): IdentifierContext {
    const params = vault.keyStore.getDerivationParameters(prefix);
    if (!params) {
      throw new IdentifierNotFoundError(`Prefix not found in key store: ${prefix}`);
    }
    return new IdentifierContext(name, prefix, vault, processor);
  }

  /** Build and sign an interaction event. */
  async makeInteractionEvent(seals: AnySeal[] = []): Promise<SignedEvent> {
    const state = this._processor.identifiers.get(this.prefix);
    if (!state) {
      throw new IdentifierNotFoundError(`No state for: ${this.prefix}`);
    }

    const sn = state.sequenceNumber + 1;
    const prior = state.latestEventSaid;

    const builder = new InteractionBuilder(defaultHashFn)
      .identifier(this.prefix)
      .previousEvent(prior)
      .sequenceNumber(sn);

    if (seals.length > 0) {
      builder.anchoredSeals(seals as unknown as Record<string, unknown>[]);
    }

    const builtEvent = builder.build();
    const signedEvent = await this._signBuiltEvent(builtEvent);

    await this._processor.ingestEvent(
      { raw: builtEvent.raw, fields: builtEvent.fields },
      signedEvent.sigers,
      { local: true },
    );

    return signedEvent;
  }

  /** Build and sign a rotation event. */
  async makeRotationEvent(opts: {
    nextCount?: number;
    nextCodes?: string[] | null;
    digestCode?: string;
    transferable?: boolean;
    testMode?: boolean;
    witnessesToAdd?: string[];
    witnessesToRemove?: string[];
    toad?: number;
  } = {}): Promise<SignedEvent> {
    const { RotationKeySetBuilder } = await import("./builders/rotation-keys.js");
    const rotKeyBuilder = new RotationKeySetBuilder()
      .forIdentifier(this.prefix)
      .nextCount(opts.nextCount ?? 1)
      .transferable(opts.transferable ?? true)
      .testMode(opts.testMode ?? false);

    if (opts.nextCodes) rotKeyBuilder.nextCodes(opts.nextCodes);
    if (opts.digestCode) rotKeyBuilder.digestCode(opts.digestCode);

    const { verfers, digers } = rotKeyBuilder.build(this._vault);

    const state = this._processor.identifiers.get(this.prefix);
    if (!state) {
      throw new IdentifierNotFoundError(`No state for: ${this.prefix}`);
    }

    const sn = state.sequenceNumber + 1;
    const prior = state.latestEventSaid;

    const rotEventBuilder = new RotationBuilder(defaultHashFn)
      .identifier(this.prefix)
      .sequenceNumber(sn)
      .previousEvent(prior)
      .signingKeys(verfers.map((v) => v.qb64))
      .nextKeys(digers.map((d) => d.qb64));

    if (opts.witnessesToAdd) rotEventBuilder.addWitnesses(opts.witnessesToAdd);
    if (opts.witnessesToRemove) rotEventBuilder.cutWitnesses(opts.witnessesToRemove);
    if (opts.toad !== undefined) rotEventBuilder.witnessThreshold(opts.toad);

    const builtEvent = rotEventBuilder.build();

    // Sign with the new current keys (which were just promoted from next keys)
    const signers: Signer[] = [];
    for (let j = 0; j < verfers.length; j++) {
      const sk = this._vault.keyStore.getPrivateKey(verfers[j].qb64, this._vault.decrypter);
      if (sk) signers.push(makeSignerFromKey(sk, j));
    }

    const signedEvent = await signEvent(builtEvent, signers);

    await this._processor.ingestEvent(
      { raw: builtEvent.raw, fields: builtEvent.fields },
      signedEvent.sigers,
      { local: true },
    );

    return signedEvent;
  }

  private async _signBuiltEvent(builtEvent: import("kel-event-processing").BuiltEvent): Promise<SignedEvent> {
    const currentKeys = this._getCurrentKeys();
    const signers: Signer[] = [];
    for (let j = 0; j < currentKeys.length; j++) {
      const sk = this._vault.keyStore.getPrivateKey(currentKeys[j], this._vault.decrypter);
      if (sk) signers.push(makeSignerFromKey(sk, j));
    }
    return signEvent(builtEvent, signers);
  }

  /** Sign a serialization with current keys. */
  sign(ser: Uint8Array): IndexedSig[] {
    const currentKeys = this._getCurrentKeys();
    return this._vault.signSerialization({
      ser,
      pubs: currentKeys,
      indexed: true,
    }) as IndexedSig[];
  }

  /** Decrypt an encrypted secret. */
  decrypt(qb64: string): Uint8Array {
    const currentKeys = this._getCurrentKeys();
    return this._vault.decryptSecret({ qb64, pubs: currentKeys });
  }

  /** Produce unindexed (Cigar) signatures. */
  endorse(ser: Uint8Array): UnindexedSig[] {
    const currentKeys = this._getCurrentKeys();
    return this._vault.signSerialization({
      ser,
      pubs: currentKeys,
      indexed: false,
    }) as UnindexedSig[];
  }

  // ── Properties ───────────────────────────────────────────────────────

  /** BC-1 key state aggregate. */
  get keyState(): IdentifierState {
    const state = this._processor.identifiers.get(this.prefix);
    if (state) return state;
    // Return empty state using Object.create to bypass private constructor
    return Object.create(IdentifierState.prototype) as IdentifierState;
  }

  /** True if next keys exist. */
  get isTransferable(): boolean {
    const situation = this._vault.keyStore.getKeySituation(this.prefix);
    return (situation?.next.pubs.length ?? 0) > 0;
  }

  /** True if delegator prefix is set. */
  get isDelegated(): boolean {
    const state = this._processor.identifiers.get(this.prefix);
    return !!state?.delegatorPrefix && state.delegatorPrefix !== "";
  }

  /** Key creation algorithm for this identifier. */
  get algorithm(): KeyAlgorithm {
    const params = this._vault.keyStore.getDerivationParameters(this.prefix);
    return (params?.algorithm as KeyAlgorithm) ?? KeyAlgorithm.DETERMINISTIC;
  }

  private _getCurrentKeys(): string[] {
    const situation = this._vault.keyStore.getKeySituation(this.prefix);
    return situation?.current.pubs ?? [];
  }
}
