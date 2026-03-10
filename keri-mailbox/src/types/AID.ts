/** Branded string type for KERI Autonomous Identifier strings (qb64-encoded prefixes). */
export type AID = string & { readonly __brand: "AID" };

/** Cast a plain string to AID without runtime validation. */
export function toAID(s: string): AID {
  return s as AID;
}
