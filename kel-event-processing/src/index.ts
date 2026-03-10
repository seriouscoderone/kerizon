// ── Types ────────────────────────────────────────────────────────────
export {
  Ilk,
  ESTABLISHMENT_ILKS,
  INCEPTION_ILKS,
  ROTATION_ILKS,
  DELEGATED_ILKS,
  Traits,
  EVENT_FIELD_ORDER,
  SAID_FIELDS,
  parseTraits,
} from "./types.js";
export type {
  Threshold,
  Seal,
  CommonFields,
  IcpFields,
  RotFields,
  IxnFields,
  DipFields,
  DrtFields,
  RctFields,
  EventFields,
  EventSealFields,
  DigestSealFields,
  RootSealFields,
  SourceSealFields,
  LastEstSealFields,
  BackerSealFields,
  KindSealFields,
  AnySeal,
  EstablishmentDetail,
  KeyStateSnapshot,
  EstablishmentLocator,
  EventProvenance,
} from "./types.js";

// ── Errors ───────────────────────────────────────────────────────────
export {
  ValidationError,
  OutOfOrderError,
  InsufficientSignaturesError,
  InsufficientWitnessesError,
  MissingDelegationError,
  PendingDelegationApprovalError,
  ProvenanceMismatchError,
  UnverifiedWitnessReceiptError,
  UnverifiedReceiptError,
  UnverifiedTransferableReceiptError,
  DuplicitousEventError,
} from "./errors.js";

// ── Config ───────────────────────────────────────────────────────────
export {
  DEFAULT_PROCESSOR_CONFIG,
  DEFAULT_ESCROW_TIMEOUTS,
} from "./config.js";
export type { ProcessorConfig, EscrowTimeouts } from "./config.js";

// ── Domain events ────────────────────────────────────────────────────
export { DomainEventBus } from "./domain-events.js";
export type {
  EventAccepted,
  EventNoticed,
  WitnessReceiptNeeded,
  EventQueryNeeded,
  CloneMismatchDetected,
  RemoteGroupSignatureReceived,
  DomainEvent,
} from "./domain-events.js";

// ── Builders ─────────────────────────────────────────────────────────
export { InceptionBuilder } from "./builders/inception.js";
export { RotationBuilder } from "./builders/rotation.js";
export { InteractionBuilder } from "./builders/interaction.js";
export { DelegatedInceptionBuilder } from "./builders/delegated-inception.js";
export { DelegatedRotationBuilder } from "./builders/delegated-rotation.js";
export { ReceiptBuilder } from "./builders/receipt.js";
export {
  EventSeal,
  DigestSeal,
  RootSeal,
  SourceSeal,
  LastEstSeal,
  BackerSeal,
  KindSeal,
} from "./builders/seals.js";
export { BuiltEvent, signEvent } from "./builders/signed-event.js";
export type { Signer, SignedEvent } from "./builders/signed-event.js";

// ── Views ────────────────────────────────────────────────────────────
export { KeyStateView } from "./views/key-state.js";
export { EscrowReason } from "./views/pending-event.js";
export type { PendingEvent } from "./views/pending-event.js";

// ── Verification ─────────────────────────────────────────────────────
export {
  publicKeyBytesFromQb64,
  verifySigs,
  satisfyThreshold,
  validateSigs,
  thresholdSize,
  ampleSufficient,
  verifyPreRotation,
  verifyCigar,
  verifyCigars,
  verifyWitnessSigs,
} from "./verification.js";
export type {
  CryptoProvider,
  IndexedSiger,
  CigarSig,
  VerifySigsResult,
  WitnessVerifyResult,
} from "./verification.js";

// ── Repository ───────────────────────────────────────────────────────
export { EscrowType } from "./repository/interface.js";
export type {
  EventRepository,
  NonTransferableReceipt,
  TransferableReceipt,
} from "./repository/interface.js";
export { digestKey, sequenceKey } from "./repository/keys.js";
export { InMemoryEventRepository, DefaultCryptoProvider } from "./repository/memory.js";

// ── Core domain ──────────────────────────────────────────────────────
export { IdentifierState } from "./identifier-state.js";
export { EventProcessor } from "./event-processor.js";
