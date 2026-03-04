// ─── Value types ─────────────────────────────────────────────────────────────
export type { AID } from "./types/AID.js";
export { toAID } from "./types/AID.js";
export type { TopicAddress } from "./types/TopicAddress.js";
export { topicKey } from "./types/TopicAddress.js";
export type { Cursor } from "./types/Cursor.js";
export type { Envelope } from "./types/Envelope.js";
export type { KeyState } from "./types/KeyState.js";
export type {
  Threshold,
  SimpleThreshold,
  WeightedThreshold,
} from "./types/Threshold.js";
export type {
  StoreResult,
  EgressEvent,
  SubmitParams,
  SubmitResult,
  PollParams,
  ProvisionResult,
} from "./types/results.js";

// ─── Dependency-injection contracts ──────────────────────────────────────────
export type { IMailboxStore } from "./interfaces/IMailboxStore.js";
export type { IKeyStateResolver } from "./interfaces/IKeyStateResolver.js";

// ─── Core utilities (cesr-ts integration) ────────────────────────────────────
export { parseSad } from "./core/SadParser.js";
export type { SadFields, ParsedMessage } from "./core/SadParser.js";

export { parseAttachments } from "./core/AttachmentParser.js";
export type {
  IndexedSig,
  CoupledSig,
  ParsedAttachments,
} from "./core/AttachmentParser.js";

export { evaluateThreshold } from "./core/ThresholdEvaluator.js";
export type { ThresholdInput } from "./core/ThresholdEvaluator.js";

export { generateNonce, verifyResponse } from "./core/ChallengeResponse.js";

// ─── Concrete service classes (DI constructors) ───────────────────────────────
export { MailboxIngress } from "./services/MailboxIngress.js";
export type { MailboxIngressOptions } from "./services/MailboxIngress.js";

export { MailboxEgress } from "./services/MailboxEgress.js";
export type { MailboxEgressOptions } from "./services/MailboxEgress.js";

export { MailboxProvisioner } from "./services/MailboxProvisioner.js";
export type { MailboxProvisionerOptions } from "./services/MailboxProvisioner.js";

// ─── Reference implementations (for testing / prototyping) ───────────────────
export { MemoryMailboxStore } from "./memory/MemoryMailboxStore.js";
export { MockKeyStateResolver } from "./memory/MockKeyStateResolver.js";
