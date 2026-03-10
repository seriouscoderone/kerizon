/** References a specific event in another KEL. */
export interface EventSeal {
  i: string;
  s: string;
  d: string;
}

/** Anchors a digest of arbitrary external data. */
export interface DigestSeal {
  d: string;
}

/** Anchors a Merkle tree root digest. */
export interface RootSeal {
  rd: string;
}

/** References an event by sn and digest (AID implied by context). */
export interface SourceSeal {
  s: string;
  d: string;
}

/** References the latest establishment event for an AID. */
export interface LastEstSeal {
  i: string;
}

/** References backer metadata. */
export interface BackerSeal {
  bi: string;
  d: string;
}

/** Typed/versioned digest seal. */
export interface KindSeal {
  t: string;
  d: string;
}

export type AnySeal =
  | EventSeal
  | DigestSeal
  | RootSeal
  | SourceSeal
  | LastEstSeal
  | BackerSeal
  | KindSeal;
