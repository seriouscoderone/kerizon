/** Event type (ilk) codes as defined in the KERI specification. */
export enum Ilk {
  /** Inception — creates a non-delegated identifier. */
  Inception = "icp",
  /** Rotation — updates keys/witnesses for a non-delegated identifier. */
  Rotation = "rot",
  /** Interaction — anchors data without changing key state. */
  Interaction = "ixn",
  /** Delegated inception — creates a delegated identifier. */
  DelegatedInception = "dip",
  /** Delegated rotation — updates a delegated identifier. */
  DelegatedRotation = "drt",
  /** Receipt — witness/validator acknowledgment. */
  Receipt = "rct",
}

/** Set of establishment event ilks (events that change key state). */
export const ESTABLISHMENT_ILKS = new Set([
  Ilk.Inception,
  Ilk.Rotation,
  Ilk.DelegatedInception,
  Ilk.DelegatedRotation,
]);

/** Set of inception event ilks. */
export const INCEPTION_ILKS = new Set([Ilk.Inception, Ilk.DelegatedInception]);

/** Set of rotation event ilks. */
export const ROTATION_ILKS = new Set([Ilk.Rotation, Ilk.DelegatedRotation]);

/** Set of delegated event ilks. */
export const DELEGATED_ILKS = new Set([
  Ilk.DelegatedInception,
  Ilk.DelegatedRotation,
]);

/** Known configuration trait codes. */
export const Traits = {
  /** Establishment Only — only establishment events allowed. */
  EstablishmentOnly: "EO",
  /** Do Not Delegate — this identifier cannot serve as a delegator. */
  DoNotDelegate: "DND",
} as const;

/** Signing threshold — simple integer string or weighted fractional. */
export type Threshold = string | string[][];

/** A seal — opaque typed reference in the `a` field. */
export type Seal = Record<string, unknown>;

// ── Event field interfaces ──────────────────────────────────────────

/** Common fields present in all KEL events. */
export interface CommonFields {
  v: string;
  t: string;
  d: string;
  i: string;
  s: string;
}

/** Fields specific to an inception event (icp). */
export interface IcpFields extends CommonFields {
  t: "icp";
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  b: string[];
  c: string[];
  a: Seal[];
}

/** Fields specific to a rotation event (rot). */
export interface RotFields extends CommonFields {
  t: "rot";
  p: string;
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  br: string[];
  ba: string[];
  a: Seal[];
}

/** Fields specific to an interaction event (ixn). */
export interface IxnFields extends CommonFields {
  t: "ixn";
  p: string;
  a: Seal[];
}

/** Fields specific to a delegated inception event (dip). */
export interface DipFields extends CommonFields {
  t: "dip";
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  b: string[];
  c: string[];
  a: Seal[];
  di: string;
}

/** Fields specific to a delegated rotation event (drt). */
export interface DrtFields extends CommonFields {
  t: "drt";
  p: string;
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  br: string[];
  ba: string[];
  a: Seal[];
}

/** Fields for a receipt event (rct). */
export interface RctFields {
  v: string;
  t: "rct";
  d: string;
  i: string;
  s: string;
}

/** Union of all KEL event field types. */
export type EventFields =
  | IcpFields
  | RotFields
  | IxnFields
  | DipFields
  | DrtFields
  | RctFields;

// ── Seal type interfaces ────────────────────────────────────────────

/** References a specific event in another KEL. */
export interface EventSealFields {
  i: string;
  s: string;
  d: string;
}

/** Anchors a digest of arbitrary external data. */
export interface DigestSealFields {
  d: string;
}

/** Anchors a Merkle tree root digest. */
export interface RootSealFields {
  rd: string;
}

/** References an event by sn and digest (AID implied by context). */
export interface SourceSealFields {
  s: string;
  d: string;
}

/** References the latest establishment event for an AID. */
export interface LastEstSealFields {
  i: string;
}

/** References backer metadata. */
export interface BackerSealFields {
  bi: string;
  d: string;
}

/** Typed/versioned digest seal. */
export interface KindSealFields {
  t: string;
  d: string;
}

export type AnySeal =
  | EventSealFields
  | DigestSealFields
  | RootSealFields
  | SourceSealFields
  | LastEstSealFields
  | BackerSealFields
  | KindSealFields;

// ── Value objects ───────────────────────────────────────────────────

/** Last establishment event info within a KeyStateSnapshot. */
export interface EstablishmentDetail {
  /** Sequence number of the last establishment event (hex). */
  s: string;
  /** SAID of the last establishment event. */
  d: string;
  /** Witnesses removed in last establishment event. */
  br: string[];
  /** Witnesses added in last establishment event. */
  ba: string[];
}

/**
 * Serializable value object projecting the complete key state of an
 * identifier at a point in time.
 */
export interface KeyStateSnapshot {
  /** Protocol version [major, minor]. */
  vn: [number, number];
  /** AID prefix qb64. */
  i: string;
  /** Sequence number (hex). */
  s: string;
  /** Prior event SAID. */
  p: string;
  /** Latest event SAID. */
  d: string;
  /** First-seen ordinal (hex). */
  f: string;
  /** ISO-8601 datetime of state update. */
  dt: string;
  /** Latest event type (ilk). */
  et: string;
  /** Current signing threshold. */
  kt: Threshold;
  /** Current signing keys qb64. */
  k: string[];
  /** Next rotation threshold. */
  nt: Threshold;
  /** Next key digests qb64. */
  n: string[];
  /** Witness threshold (hex). */
  bt: string;
  /** Current witness prefixes qb64. */
  b: string[];
  /** Configuration traits. */
  c: string[];
  /** Last establishment event info. */
  ee: EstablishmentDetail;
  /** Delegator prefix (empty string if not delegated). */
  di: string;
}

/** Pairs (sequence number, digest) to locate the last establishment event. */
export interface EstablishmentLocator {
  /** Sequence number of last establishment event. */
  sn: number;
  /** SAID of last establishment event. */
  digest: string;
}

/** Marks whether an event originated locally or remotely. */
export interface EventProvenance {
  /** true if event originated from a locally-controlled source. */
  local: boolean;
}

// ── Schema constants ────────────────────────────────────────────────

/** Field order definitions per ilk (v1.0). Fields MUST appear in this order. */
export const EVENT_FIELD_ORDER: Record<string, readonly string[]> = {
  [Ilk.Inception]: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"],
  [Ilk.Rotation]: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
  [Ilk.Interaction]: ["v", "t", "d", "i", "s", "p", "a"],
  [Ilk.DelegatedInception]: ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"],
  [Ilk.DelegatedRotation]: ["v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a"],
  [Ilk.Receipt]: ["v", "t", "d", "i", "s"],
};

/** Fields that are SAID-computed for each ilk. */
export const SAID_FIELDS: Record<string, readonly string[]> = {
  [Ilk.Inception]: ["d", "i"],
  [Ilk.Rotation]: ["d"],
  [Ilk.Interaction]: ["d"],
  [Ilk.DelegatedInception]: ["d", "i"],
  [Ilk.DelegatedRotation]: ["d"],
  [Ilk.Receipt]: [],
};

/** Parse configuration traits from a `c` field array. */
export function parseTraits(c: string[]): {
  estOnly: boolean;
  doNotDelegate: boolean;
} {
  return {
    estOnly: c.includes(Traits.EstablishmentOnly),
    doNotDelegate: c.includes(Traits.DoNotDelegate),
  };
}
