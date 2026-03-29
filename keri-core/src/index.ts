/**
 * @kerizon/keri-core — KERI key event creation functions.
 */

export { incept } from './events/inception.js';
export { rotate } from './events/rotation.js';
export { interact } from './events/interaction.js';

export type {
  EventType,
  InceptConfig,
  RotateConfig,
  InteractConfig,
} from './events/types.js';

export {
  ICP_FIELDS,
  ROT_FIELDS,
  IXN_FIELDS,
  DIP_FIELDS,
  DRT_FIELDS,
} from './events/types.js';

export { computeNextDigest, verifyPreRotation } from './key-commitment/pre-rotation.js';
export { isTransferable, isTransferableCode } from './key-commitment/transferability.js';

export { Kever } from './state/kever.js';
export { TraitDex } from './state/traits.js';

export { checkDualThreshold } from './thresholds/dual-threshold.js';
export type { DualThresholdResult } from './thresholds/types.js';
export { buildWitnessConfig, applyWitnessChanges, enoughReceipts } from './thresholds/witness-config.js';
export type { WitnessConfiguration } from './thresholds/witness-config.js';

export { exchange } from './messaging/exchange.js';
export { query } from './messaging/query.js';
export { reply } from './messaging/reply.js';
export type {
  MessageType,
  ExchangeConfig,
  QueryConfig,
  ReplyConfig,
} from './messaging/types.js';

export { createDuplicityStatus } from './watcher/types.js';
export type { DuplicityStatus, WatcherPort } from './watcher/types.js';

export { createDelegatedInception, createDelegationSeal } from './delegation/create.js';
export { verifyDelegationSeal, findDelegationSeal } from './delegation/verify.js';
export type { DelegatedInceptionConfig, DelegationSeal } from './delegation/types.js';

export { createReceipt, classifyReceipt } from './receipting/create.js';
export type { CreateReceiptOpts } from './receipting/create.js';
export type { Receipt, ReceiptType } from './receipting/types.js';

export { buildApply, buildOffer, buildAgree, buildGrant, buildAdmit, buildSpurn } from './credential-exchange/ipex.js';
export { NegotiationStateMachine } from './credential-exchange/thread.js';
export { NegotiationState, IPEX_ROUTES, VALID_TRANSITIONS } from './credential-exchange/types.js';
export type {
  IpexRoute,
  ApplyConfig,
  OfferConfig,
  AgreeConfig,
  GrantConfig,
  AdmitConfig,
  SpurnConfig,
} from './credential-exchange/types.js';

export { createRegistry, createUpdate } from './credential-lifecycle/registry.js';
export type { CreateRegistryConfig, CreateUpdateConfig } from './credential-lifecycle/registry.js';
export { TelStateMachine } from './credential-lifecycle/tel.js';
export { TEL_VALID_TRANSITIONS } from './credential-lifecycle/types.js';
export type { CredentialState, CredentialStatus } from './credential-lifecycle/types.js';

export { detectFork, isForked } from './evidence/detect.js';
export type { EventRef } from './evidence/detect.js';
export type { ForkDetected } from './evidence/types.js';

export { KERL } from './accountability/kerl.js';
export type { ReceiptRef } from './accountability/kerl.js';
export { checkAccountability, ample } from './accountability/kawa.js';
export type { AccountabilityResult } from './accountability/kawa.js';

export { verifyCredentialArtifacts, verifyProofChain } from './credential-proof/verify.js';
export type { CredentialArtifacts, ProofChain } from './credential-proof/verify.js';
export type { ProofResult, RegistryState } from './credential-proof/types.js';
