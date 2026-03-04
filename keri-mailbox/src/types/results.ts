import type { AID } from "./AID.js";
import type { TopicAddress } from "./TopicAddress.js";

/** Result of storing a message. */
export interface StoreResult {
  ordinal: bigint;
  digest: string;
}

/** One message event delivered during egress polling. */
export interface EgressEvent {
  topic: TopicAddress;
  ordinal: bigint;
  payload: Uint8Array;
}

/** Parameters for submitting a message via MailboxIngress. */
export interface SubmitParams {
  sender: AID;
  recipient: AID;
  topic: string;
  payload: Uint8Array;
  /** Raw CESR attachment bytes for sender signature verification (if requireSenderAuth is true). */
  attachments?: Uint8Array;
}

/** Result of a successful submit. */
export interface SubmitResult {
  ordinal: bigint;
  digest: string;
}

/** Parameters for polling messages via MailboxEgress. */
export interface PollParams {
  recipient: AID;
  /** Map of topic name → last-seen ordinal (exclusive lower bound, use 0n for all). */
  cursors: Map<string, bigint>;
  /** Challenge nonce for egress authentication (from generateNonce()). */
  challenge?: string;
  /** qb64-encoded signature of the challenge nonce. */
  signature?: string;
}

/** Result of processing a /end/role/add or /end/role/cut reply. */
export type ProvisionResult =
  | { ok: true; aid: AID }
  | { ok: false; reason: string };
