import { parseBytes } from "cesr-ts";
import type { AttachmentGroup } from "cesr-ts";

/** Outer fields of a KERI SAD (Self-Addressing Data) message. */
export interface SadFields {
  /** Protocol version string, e.g. "KERI10JSON0000aa_" */
  v?: string;
  /** Event type / ilk, e.g. "icp", "rpy", "exn" */
  t?: string;
  /** SAID of the message */
  d?: string;
  /** Route, e.g. "/end/role/add" */
  r?: string;
  /** Attributes map */
  a?: unknown;
  /** Edges (for ACDC) */
  e?: unknown;
  /** Query fields */
  q?: unknown;
  [key: string]: unknown;
}

/** Result of parsing a CESR-encoded KERI message. */
export interface ParsedMessage {
  /** Outer fields from the key event dictionary. */
  fields: SadFields;
  /** Raw bytes of the SAD body (used for signature verification). */
  raw: Uint8Array;
  /** Parsed CESR attachment groups following the body. */
  attachments: AttachmentGroup[];
}

/**
 * Parse the outer structure of a CESR-encoded KERI SAD message.
 *
 * Does NOT validate SAIDs or signatures — use ThresholdEvaluator for that.
 * Throws if the bytes cannot be parsed as a valid CESR frame.
 */
export function parseSad(bytes: Uint8Array): ParsedMessage {
  const frames = parseBytes(bytes);
  if (frames.length === 0) {
    throw new Error("Empty CESR stream: no frames parsed");
  }
  const first = frames[0];
  if (first.type === "error") {
    throw first.error;
  }
  const { body, attachments } = first.frame;
  if (!body.ked) {
    throw new Error("No KED (key event dictionary) in parsed CESR frame");
  }
  return {
    fields: body.ked as SadFields,
    raw: body.raw,
    attachments,
  };
}
