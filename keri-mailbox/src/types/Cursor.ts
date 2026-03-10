import type { TopicAddress } from "./TopicAddress.js";

/** A position in a topic's message stream. */
export interface Cursor {
  topic: TopicAddress;
  ordinal: bigint;
}
