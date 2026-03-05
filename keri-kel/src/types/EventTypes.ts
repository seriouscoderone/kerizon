/** Event type (ilk) codes as defined in the KERI specification. */
export enum Ilk {
  /** Inception — creates a non-delegated identifier. */
  icp = "icp",
  /** Rotation — updates keys/witnesses for a non-delegated identifier. */
  rot = "rot",
  /** Interaction — anchors data without changing key state. */
  ixn = "ixn",
  /** Delegated inception — creates a delegated identifier. */
  dip = "dip",
  /** Delegated rotation — updates a delegated identifier. */
  drt = "drt",
  /** Receipt — witness/validator acknowledgment. */
  rct = "rct",
}

/** Set of establishment event ilks (events that change key state). */
export const ESTABLISHMENT_ILKS = new Set([Ilk.icp, Ilk.rot, Ilk.dip, Ilk.drt]);

/** Set of inception event ilks. */
export const INCEPTION_ILKS = new Set([Ilk.icp, Ilk.dip]);

/** Set of rotation event ilks. */
export const ROTATION_ILKS = new Set([Ilk.rot, Ilk.drt]);

/** Set of delegated event ilks. */
export const DELEGATED_ILKS = new Set([Ilk.dip, Ilk.drt]);

/** Signing threshold — simple integer string or weighted fractional. */
export type Threshold = string | string[][];

/** Common fields present in all KEL events. */
export interface CommonFields {
  /** Version string (e.g., "KERI10JSON000120_"). */
  v: string;
  /** Event type / ilk code. */
  t: string;
  /** SAID of this event. */
  d: string;
  /** AID prefix. */
  i: string;
  /** Sequence number as hex string. */
  s: string;
}

/** Fields specific to an inception event (icp). */
export interface IcpFields extends CommonFields {
  t: "icp";
  /** Signing threshold. */
  kt: Threshold;
  /** Current signing keys (Verfer qb64 values). */
  k: string[];
  /** Next rotation threshold. */
  nt: Threshold;
  /** Next key digests (Diger qb64 values). */
  n: string[];
  /** Witness threshold (TOAD) as hex string. */
  bt: string;
  /** Witness AID prefixes. */
  b: string[];
  /** Configuration traits (e.g., "EO", "DND"). */
  c: string[];
  /** Seal list. */
  a: Seal[];
}

/** Fields specific to a rotation event (rot). */
export interface RotFields extends CommonFields {
  t: "rot";
  /** SAID of prior event. */
  p: string;
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  /** Witnesses removed. */
  br: string[];
  /** Witnesses added. */
  ba: string[];
  /** Seal list. */
  a: Seal[];
}

/** Fields specific to an interaction event (ixn). */
export interface IxnFields extends CommonFields {
  t: "ixn";
  /** SAID of prior event. */
  p: string;
  /** Seal list. */
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
  /** Delegator AID prefix. */
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
  /** SAID of the receipted event. */
  d: string;
  /** AID of the receipted event. */
  i: string;
  /** Sequence number of the receipted event. */
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

/** A seal — opaque typed reference in the `a` field. */
export type Seal = Record<string, unknown>;
