import type { AID } from "./AID.js";

/** Identifies a named message topic within a recipient's mailbox. */
export interface TopicAddress {
  recipient: AID;
  topic: string;
}

/** Stable string key for a TopicAddress usable as a Map key. */
export function topicKey(addr: TopicAddress): string {
  return `${addr.recipient}/${addr.topic}`;
}
