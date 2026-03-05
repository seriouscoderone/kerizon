/** Known configuration trait codes. */
export const Traits = {
  /** Establishment Only — only establishment events allowed. */
  EO: "EO",
  /** Do Not Delegate — this identifier cannot serve as a delegator. */
  DND: "DND",
  /** Registrar Backers. */
  RB: "RB",
  /** No Backers (deprecated, use NRB). */
  NB: "NB",
  /** No Registrar Backers. */
  NRB: "NRB",
  /** Delegate Is Delegator. */
  DID: "DID",
} as const;

/** Parse configuration traits from a `c` field array. */
export function parseTraits(c: string[]): {
  estOnly: boolean;
  doNotDelegate: boolean;
} {
  return {
    estOnly: c.includes(Traits.EO),
    doNotDelegate: c.includes(Traits.DND),
  };
}
