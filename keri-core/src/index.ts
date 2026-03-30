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
export { RegistryManager } from './credential-lifecycle/manager.js';
export { TEL_VALID_TRANSITIONS } from './credential-lifecycle/types.js';
export type { CredentialState, CredentialStatus, RegistryMode, RegistryRecord } from './credential-lifecycle/types.js';

export { detectFork, isForked } from './evidence/detect.js';
export type { EventRef } from './evidence/detect.js';
export type { ForkDetected } from './evidence/types.js';

export { DuplicityEventLog } from './integrity/del.js';
export { SupersedingRule, canSupersede } from './integrity/superseding.js';
export type { SupersedingCandidate } from './integrity/superseding.js';
export type {
  DuplicityEvidence,
  SupersedingRecoveryEvent,
  DisputedBranch,
  TrustDecision,
} from './integrity/types.js';

export type {
  EventSubmissionResult,
  KERLResponse,
  WitnessServicePort,
} from './witness-api/types.js';

export { KERL } from './accountability/kerl.js';
export type { ReceiptRef } from './accountability/kerl.js';
export { checkAccountability, ample } from './accountability/kawa.js';
export type { AccountabilityResult } from './accountability/kawa.js';
export { buildDisseminationPlan, classifyMode } from './accountability/dissemination.js';
export type { DisseminationConfig, DisseminationPlan } from './accountability/dissemination.js';

export { verifyCredentialArtifacts, verifyProofChain } from './credential-proof/verify.js';
export type { CredentialArtifacts, ProofChain } from './credential-proof/verify.js';
export type { ProofResult, RegistryState } from './credential-proof/types.js';

export { parseOobi, formatOobi, shouldAccept } from '@kerizon/discovery';
export type {
  OobiRole,
  OobiParts,
  EndRole,
  LocationScheme,
  ServiceEndpoint,
  ResolvedEndpoint,
  BadaTier,
  BadaRecord,
} from '@kerizon/discovery';

export { EscrowStore } from './identity/escrow.js';
export { processEvent } from './identity/process.js';
export type { KeverStore } from './identity/process.js';
export type { EscrowType, EscrowedEvent, ProcessResult } from './identity/types.js';

export { CredentialExchange } from './credential-exchange/orchestrator.js';

export { CredentialLifecycle } from './credential-lifecycle/facade.js';

export { classifyPrivacyLevel, validateDisclosure } from './privacy/disclosure.js';
export type { PrivacyLevel, DisclosureType, DisclosureRequest } from './privacy/types.js';
export { computeBlid, deriveUuid, verifyBlid } from './privacy/blinding.js';
export { computeSadPathDigest, computeAggregate, verifyInclusion } from './privacy/aggregation.js';

export { WatcherService } from './watcher-service/orchestrator.js';

export type { LocalAgentPort } from './local-agent/types.js';
export { LocalAgent } from './local-agent/agent.js';
export type { LocalAgentIdentity } from './local-agent/agent.js';

export type { SecurityTier, Keeper, SignifyClient } from './signify-client/types.js';
export { SimpleKeeper } from './signify-client/keeper.js';
export type {
  IdentifierResource,
  CredentialResource,
  RegistryResource,
  ExchangeResource,
  OobiResource,
  SignifyResources,
} from './signify-client/resources.js';

export type { AgentConfig, CloudAgentPort } from './cloud-agent/types.js';
export { AgentManager } from './cloud-agent/manager.js';
export type { BootEndpoint, AdminEndpoint, EventProcessor } from './cloud-agent/api.js';
