import type {
  EventSeal,
  DigestSeal,
  RootSeal,
  SourceSeal,
  LastEstSeal,
  BackerSeal,
  KindSeal,
} from "../types/Seals.js";

/** Factory for EventSeal — references a specific event in another KEL. */
export function eventSeal(
  identifier: string,
  sequenceNumber: number,
  digest: string,
): EventSeal {
  return {
    i: identifier,
    s: sequenceNumber.toString(16),
    d: digest,
  };
}

/** Factory for DigestSeal — anchors a digest of arbitrary external data. */
export function digestSeal(digest: string): DigestSeal {
  return { d: digest };
}

/** Factory for RootSeal — anchors a Merkle tree root digest. */
export function rootSeal(digest: string): RootSeal {
  return { rd: digest };
}

/** Factory for SourceSeal — references an event by sn and digest. */
export function sourceSeal(sequenceNumber: number, digest: string): SourceSeal {
  return {
    s: sequenceNumber.toString(16),
    d: digest,
  };
}

/** Factory for LastEstSeal — references the latest establishment event. */
export function lastEstSeal(identifier: string): LastEstSeal {
  return { i: identifier };
}

/** Factory for BackerSeal — references backer metadata. */
export function backerSeal(backerPrefix: string, digest: string): BackerSeal {
  return { bi: backerPrefix, d: digest };
}

/** Factory for KindSeal — typed/versioned digest seal. */
export function kindSeal(typeVersion: string, digest: string): KindSeal {
  return { t: typeVersion, d: digest };
}
