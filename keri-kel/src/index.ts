// Types
export {
  Ilk,
  ESTABLISHMENT_ILKS,
  INCEPTION_ILKS,
  ROTATION_ILKS,
  DELEGATED_ILKS,
  EscrowReason,
  ESCROW_TIMEOUTS,
  KelError,
  StructuralError,
  SequenceError,
  SignatureError,
  PreRotationError,
  DuplicityError,
  OutOfOrderError,
  DelegationError,
  WitnessError,
  ConfigError,
} from "./types/index.js";

export type {
  Threshold,
  CommonFields,
  IcpFields,
  RotFields,
  IxnFields,
  DipFields,
  DrtFields,
  RctFields,
  EventFields,
  Seal,
  EventSeal,
  DigestSeal,
  RootSeal,
  SourceSeal,
  LastEstSeal,
  BackerSeal,
  KindSeal,
  AnySeal,
  KeyStateRecord,
  StateEstEvent,
  PendingEvent,
  VerificationResult,
  Accepted,
  Escrowed,
  Rejected,
} from "./types/index.js";

// Interfaces
export type { ICryptoProvider } from "./interfaces/ICryptoProvider.js";
export type { IEventDatabase } from "./interfaces/IEventDatabase.js";
export type { IEscrowStore, EscrowEntry, SealInfo } from "./interfaces/IEscrowStore.js";
export type {
  IReceiptStore,
  NonTransReceipt,
  TransReceipt,
  ReceiptSet,
} from "./interfaces/IReceiptStore.js";

// Seal builders
export {
  eventSeal,
  digestSeal,
  rootSeal,
  sourceSeal,
  lastEstSeal,
  backerSeal,
  kindSeal,
} from "./builders/SealBuilders.js";

// Event schemas and config
export { EVENT_FIELD_ORDER, SAID_FIELDS } from "./core/events/schemas.js";
export { Traits, parseTraits } from "./core/events/configTraits.js";

// Layer 1 — Signature verification
export { verifySigs, publicKeyBytesFromQb64 } from "./core/signature/verifySigs.js";
export type { IndexedSiger, VerifySigsResult } from "./core/signature/verifySigs.js";
export { satisfyThreshold, thresholdSize } from "./core/signature/satisfyThreshold.js";
export { verifyPreRotation } from "./core/signature/verifyPreRotation.js";
export { verifyCigar, verifyCigars } from "./core/signature/verifyCigar.js";

// Layer 2 — Event structure
export { computeSaid, makeVersionString, buildEventWithVersion } from "./core/events/computeSaid.js";
export { validateStructure, parseVersionString } from "./core/events/validateStructure.js";
export { deriveBacks } from "./core/events/deriveBacks.js";

// Layer 3 — Key state
export { Kever } from "./core/state/Kever.js";

// Layer 4 — Witnessing
export { ample } from "./core/witness/ample.js";
export { verifyWitnessSigs } from "./core/witness/verifyWitnessSigs.js";

// Layer 5 — Delegation
export { validateDelegation } from "./core/delegation/validateDelegation.js";
export { isValidSupersede, delegationSealSupersedes } from "./core/delegation/supersedingRules.js";

// Layer 6 — Event processing
export { Kevery } from "./core/processing/Kevery.js";

// Layer 7 — Escrow
export { EscrowManager } from "./core/escrow/EscrowManager.js";
export { ESCROW_CONFIGS, ESCROW_PROCESSING_ORDER } from "./core/escrow/escrowTypes.js";

// Layer 8 — Builders
export { InceptionBuilder } from "./builders/InceptionBuilder.js";
export { RotationBuilder } from "./builders/RotationBuilder.js";
export { InteractionBuilder } from "./builders/InteractionBuilder.js";
export { DelegatedInceptionBuilder } from "./builders/DelegatedInceptionBuilder.js";
export { DelegatedRotationBuilder } from "./builders/DelegatedRotationBuilder.js";
export { ReceiptBuilder } from "./builders/ReceiptBuilder.js";

// Layer 8 — Pipeline
export { VerificationPipeline } from "./pipeline/VerificationPipeline.js";
export type { PipelineOptions } from "./pipeline/VerificationPipeline.js";
export { signEvent } from "./pipeline/SignedEvent.js";
export type { BuiltEvent, Signer, SignedEvent } from "./pipeline/SignedEvent.js";

// Layer 8 — Views
export { KeyStateView } from "./views/KeyState.js";
export { EscrowQuery } from "./views/EscrowQuery.js";

// Memory implementations
export { MemoryEventDatabase } from "./memory/MemoryEventDatabase.js";
export { MemoryEscrowStore } from "./memory/MemoryEscrowStore.js";
export { MemoryReceiptStore } from "./memory/MemoryReceiptStore.js";
export { DefaultCryptoProvider } from "./memory/DefaultCryptoProvider.js";
