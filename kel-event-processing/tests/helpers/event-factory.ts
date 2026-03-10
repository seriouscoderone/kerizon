/**
 * Event factory helpers for tests.
 * Provides pre-built valid events for common test scenarios.
 */
import { InceptionBuilder } from "../../src/builders/inception.js";
import { RotationBuilder } from "../../src/builders/rotation.js";
import { InteractionBuilder } from "../../src/builders/interaction.js";
import { DelegatedInceptionBuilder } from "../../src/builders/delegated-inception.js";
import { ReceiptBuilder } from "../../src/builders/receipt.js";
import type { BuiltEvent } from "../../src/builders/signed-event.js";
import type { IndexedSiger } from "../../src/verification.js";
import type { Seal } from "../../src/types.js";
import { generateKeyPair, signMessage, testHashFn } from "../helpers.js";
import type { Ed25519KeyPair } from "../helpers.js";

export interface SignedBuiltEvent {
  event: BuiltEvent;
  siger: IndexedSiger;
  keyPair: Ed25519KeyPair;
}

/** Build and sign a minimal valid inception event. */
export async function buildValidInception(options?: {
  nextKeyPair?: Ed25519KeyPair;
  witnesses?: string[];
  witnessThreshold?: number;
  traits?: string[];
  seals?: Seal[];
}): Promise<SignedBuiltEvent & { nextKeyPair: Ed25519KeyPair }> {
  const kp = await generateKeyPair();
  const nextKp = options?.nextKeyPair ?? await generateKeyPair();

  const builder = new InceptionBuilder(testHashFn)
    .signingKeys([kp.verferQb64])
    .nextKeys([nextKp.verferQb64]);

  if (options?.witnesses) builder.witnesses(options.witnesses);
  if (options?.witnessThreshold !== undefined) builder.witnessThreshold(options.witnessThreshold);
  if (options?.traits?.includes("EO")) builder.establishmentOnly();
  if (options?.traits?.includes("DND")) builder.doNotDelegate();
  if (options?.seals) builder.anchoredSeals(options.seals);

  const event = builder.build();
  const sigBytes = await signMessage(kp.privateKey, event.raw);
  const siger: IndexedSiger = {
    index: 0,
    raw: sigBytes,
    qb64: `sig_0_${Date.now()}_${Math.random()}`,
  };

  return { event, siger, keyPair: kp, nextKeyPair: nextKp };
}

/** Build and sign a rotation event following a previous event. */
export async function buildValidRotation(
  previousEvent: BuiltEvent,
  signingKeyPair: Ed25519KeyPair,
  options?: {
    nextKeyPair?: Ed25519KeyPair;
    cutWitnesses?: string[];
    addWitnesses?: string[];
    currentWitnesses?: string[];
    seals?: Seal[];
  },
): Promise<SignedBuiltEvent & { nextKeyPair: Ed25519KeyPair }> {
  const nextKp = options?.nextKeyPair ?? await generateKeyPair();

  const builder = new RotationBuilder(testHashFn)
    .identifier(previousEvent.prefix)
    .previousEvent(previousEvent.said)
    .sequenceNumber(previousEvent.sn + 1)
    .signingKeys([signingKeyPair.verferQb64])
    .nextKeys([nextKp.verferQb64]);

  if (options?.cutWitnesses) builder.cutWitnesses(options.cutWitnesses);
  if (options?.addWitnesses) builder.addWitnesses(options.addWitnesses);
  if (options?.currentWitnesses) builder.currentWitnesses(options.currentWitnesses);
  if (options?.seals) builder.anchoredSeals(options.seals);

  const event = builder.build();
  const sigBytes = await signMessage(signingKeyPair.privateKey, event.raw);
  const siger: IndexedSiger = {
    index: 0,
    raw: sigBytes,
    qb64: `sig_0_${Date.now()}_${Math.random()}`,
  };

  return { event, siger, keyPair: signingKeyPair, nextKeyPair: nextKp };
}

/** Build and sign an interaction event. */
export async function buildValidInteraction(
  previousEvent: BuiltEvent,
  signingKeyPair: Ed25519KeyPair,
  seals?: Seal[],
): Promise<SignedBuiltEvent> {
  const builder = new InteractionBuilder(testHashFn)
    .identifier(previousEvent.prefix)
    .previousEvent(previousEvent.said)
    .sequenceNumber(previousEvent.sn + 1);

  if (seals) builder.anchoredSeals(seals);

  const event = builder.build();
  const sigBytes = await signMessage(signingKeyPair.privateKey, event.raw);
  const siger: IndexedSiger = {
    index: 0,
    raw: sigBytes,
    qb64: `sig_0_${Date.now()}_${Math.random()}`,
  };

  return { event, siger, keyPair: signingKeyPair };
}

/** Build a delegated inception event. */
export async function buildValidDelegatedInception(
  delegatorPrefix: string,
): Promise<SignedBuiltEvent & { nextKeyPair: Ed25519KeyPair }> {
  const kp = await generateKeyPair();
  const nextKp = await generateKeyPair();

  const event = new DelegatedInceptionBuilder(testHashFn)
    .delegator(delegatorPrefix)
    .signingKeys([kp.verferQb64])
    .nextKeys([nextKp.verferQb64])
    .build();

  const sigBytes = await signMessage(kp.privateKey, event.raw);
  const siger: IndexedSiger = {
    index: 0,
    raw: sigBytes,
    qb64: `sig_0_${Date.now()}_${Math.random()}`,
  };

  return { event, siger, keyPair: kp, nextKeyPair: nextKp };
}

/** Build a receipt event. */
export function buildReceipt(
  prefix: string,
  sn: number,
  said: string,
): BuiltEvent {
  return new ReceiptBuilder()
    .forEvent({ prefix, sn, said })
    .build();
}
