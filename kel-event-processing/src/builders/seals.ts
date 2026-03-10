import type {
  EventSealFields,
  DigestSealFields,
  RootSealFields,
  SourceSealFields,
  LastEstSealFields,
  BackerSealFields,
  KindSealFields,
} from "../types.js";

/** Factory for EventSeal — references a specific event in another KEL. */
export class EventSeal {
  static of(identifier: string, sequenceNumber: number, digest: string): EventSealFields {
    return {
      i: identifier,
      s: sequenceNumber.toString(16),
      d: digest,
    };
  }
}

/** Factory for DigestSeal — anchors a digest of arbitrary external data. */
export class DigestSeal {
  static of(digest: string): DigestSealFields {
    return { d: digest };
  }
}

/** Factory for RootSeal — anchors a Merkle tree root digest. */
export class RootSeal {
  static of(digest: string): RootSealFields {
    return { rd: digest };
  }
}

/** Factory for SourceSeal — references an event by sn and digest. */
export class SourceSeal {
  static of(sequenceNumber: number, digest: string): SourceSealFields {
    return {
      s: sequenceNumber.toString(16),
      d: digest,
    };
  }
}

/** Factory for LastEstSeal — references the latest establishment event. */
export class LastEstSeal {
  static of(identifier: string): LastEstSealFields {
    return { i: identifier };
  }
}

/** Factory for BackerSeal — references backer metadata. */
export class BackerSeal {
  static of(backerPrefix: string, digest: string): BackerSealFields {
    return { bi: backerPrefix, d: digest };
  }
}

/** Factory for KindSeal — typed/versioned digest seal. */
export class KindSeal {
  static of(typeVersion: string, digest: string): KindSealFields {
    return { t: typeVersion, d: digest };
  }
}
