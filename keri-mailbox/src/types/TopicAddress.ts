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

/**
 * Validate a topic name per the spec:
 *   - Must start with `/`
 *   - Must contain only alphanumeric characters, hyphens, and underscores after the `/`
 *   - Must not be empty (i.e. "/" alone is invalid)
 *
 * Returns true if valid.
 */
export function isValidTopic(topic: string): boolean {
  return /^\/[A-Za-z0-9_-]+$/.test(topic);
}
