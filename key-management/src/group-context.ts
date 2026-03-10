/**
 * GroupIdentifierContext — multi-sig partial-signature coordination.
 *
 * Cross-ref: habbing.py:2622 (GroupHab)
 */
import {
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
import { type IndexedSig, type UnindexedSig } from "./cesr-helpers.js";
import type { IdentifierContext } from "./identifier-context.js";
import type { KeyVault } from "./key-vault.js";
import type { GroupKeySetBuilder } from "./builders/group-keys.js";
import { DerivationError } from "./errors.js";

const defaultHashFn: HashFn = (data: Uint8Array): Uint8Array => blake3(data);

export class GroupIdentifierContext {
  readonly signingMemberIds: string[];
  readonly rotatingMemberIds: string[];
  readonly localMember: IdentifierContext;
  private _prefix: string = "";
  private _signingThreshold: string | string[][] = "1";
  private readonly _vault: KeyVault;
  private readonly _processor: EventProcessor;

  constructor(opts: {
    signingMemberIds: string[];
    rotatingMemberIds?: string[] | null;
    localMember: IdentifierContext;
    vault: KeyVault;
    processor: EventProcessor;
  }) {
    this.signingMemberIds = [...opts.signingMemberIds];
    this.rotatingMemberIds = opts.rotatingMemberIds
      ? [...opts.rotatingMemberIds]
      : [...opts.signingMemberIds];
    this.localMember = opts.localMember;
    this._vault = opts.vault;
    this._processor = opts.processor;
  }

  get prefix(): string {
    return this._prefix;
  }

  get signingThreshold(): string | string[][] {
    return this._signingThreshold;
  }

  /**
   * Create group inception event. Each participant signs their portion.
   */
  async make(
    groupKeyBuilder: GroupKeySetBuilder,
    signingThreshold: Threshold = "1",
    nextThreshold: Threshold = "1",
    witnesses: string[] = [],
    toad = 0,
  ): Promise<SignedEvent> {
    const { verfers, digers } = groupKeyBuilder.build();

    if (verfers.length === 0) {
      throw new DerivationError("GroupIdentifierContext: no verfers from builder");
    }

    const iBuilder = new InceptionBuilder(defaultHashFn)
      .signingKeys(verfers.map((v) => v.qb64))
      .signingThreshold(signingThreshold)
      .nextKeys(digers.map((d) => d.qb64))
      .nextKeyThreshold(nextThreshold);

    if (witnesses.length > 0) iBuilder.witnesses(witnesses);
    if (toad > 0) iBuilder.witnessThreshold(toad);

    const builtEvent = iBuilder.build();
    this._prefix = builtEvent.prefix;
    this._signingThreshold =
      typeof signingThreshold === "string" ? signingThreshold : "1";

    // Sign with local member's current keys
    const localState = this._processor.identifiers.get(this.localMember.prefix);
    const localKeys = localState?.signingKeys ?? this.localMember.keyState.signingKeys;
    const localIdx = this.signingMemberIds.indexOf(this.localMember.prefix);

    const signers: Signer[] = [];
    for (let j = 0; j < localKeys.length; j++) {
      const sk = this._vault.keyStore.getPrivateKey(localKeys[j], this._vault.decrypter);
      if (sk) {
        const absIdx = localIdx >= 0 ? localIdx + j : j;
        signers.push({
          index: absIdx,
          sign: async (msg: Uint8Array) => {
            const s = sk.sign(msg, true, absIdx) as IndexedSig;
            return s.raw;
          },
        });
      }
    }

    return signEvent(builtEvent, signers);
  }

  /** Sign event using local member's keys. */
  sign(ser: Uint8Array): IndexedSig[] {
    const localKeys = this.localMember.keyState.signingKeys;
    return this._vault.signSerialization({
      ser,
      pubs: localKeys,
      indexed: true,
    }) as IndexedSig[];
  }

  /** Create group interaction event. */
  async interact(seals: AnySeal[] = []): Promise<SignedEvent> {
    const state = this._processor.identifiers.get(this._prefix);
    const sn = state ? state.sequenceNumber + 1 : 0;
    const prior = state?.latestEventSaid ?? "";

    const builder = new InteractionBuilder(defaultHashFn)
      .identifier(this._prefix)
      .previousEvent(prior)
      .sequenceNumber(sn);

    if (seals.length > 0) builder.anchoredSeals(seals as unknown as Record<string, unknown>[]);

    const builtEvent = builder.build();

    const localKeys = this.localMember.keyState.signingKeys;
    const signers: Signer[] = [];
    for (let j = 0; j < localKeys.length; j++) {
      const sk = this._vault.keyStore.getPrivateKey(localKeys[j], this._vault.decrypter);
      if (sk) {
        signers.push({
          index: j,
          sign: async (msg: Uint8Array) => {
            const s = sk.sign(msg, true, j) as IndexedSig;
            return s.raw;
          },
        });
      }
    }

    return signEvent(builtEvent, signers);
  }

  /** Create group rotation event. */
  async rotate(opts: {
    signingMembers?: string[] | null;
    rotatingMembers?: string[] | null;
    groupKeyBuilder: GroupKeySetBuilder;
    signingThreshold?: Threshold;
    nextThreshold?: Threshold;
    witnesses?: string[];
    toad?: number;
  }): Promise<SignedEvent> {
    const { verfers, digers } = opts.groupKeyBuilder.build();

    const state = this._processor.identifiers.get(this._prefix);
    const sn = state ? state.sequenceNumber + 1 : 0;
    const prior = state?.latestEventSaid ?? "";

    const rBuilder = new RotationBuilder(defaultHashFn)
      .identifier(this._prefix)
      .sequenceNumber(sn)
      .previousEvent(prior)
      .signingKeys(verfers.map((v) => v.qb64))
      .nextKeys(digers.map((d) => d.qb64));

    if (opts.signingThreshold) rBuilder.signingThreshold(opts.signingThreshold);
    if (opts.nextThreshold) rBuilder.nextKeyThreshold(opts.nextThreshold);
    if (opts.witnesses) rBuilder.addWitnesses(opts.witnesses);
    if (opts.toad !== undefined) rBuilder.witnessThreshold(opts.toad);

    const builtEvent = rBuilder.build();

    const localKeys = this.localMember.keyState.signingKeys;
    const signers: Signer[] = [];
    for (let j = 0; j < localKeys.length; j++) {
      const sk = this._vault.keyStore.getPrivateKey(localKeys[j], this._vault.decrypter);
      if (sk) {
        signers.push({
          index: j,
          sign: async (msg: Uint8Array) => {
            const s = sk.sign(msg, true, j) as IndexedSig;
            return s.raw;
          },
        });
      }
    }

    // Update member lists if changed
    if (opts.signingMembers) {
      this.signingMemberIds.splice(0, this.signingMemberIds.length, ...opts.signingMembers);
    }
    if (opts.rotatingMembers) {
      this.rotatingMemberIds.splice(0, this.rotatingMemberIds.length, ...opts.rotatingMembers);
    }

    return signEvent(builtEvent, signers);
  }
}
