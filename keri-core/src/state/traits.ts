/**
 * Configuration trait codes for KERI identifiers.
 *
 * Traits are set at inception and are cumulative/irreversible:
 * once a trait is added, it cannot be removed by subsequent events.
 */
export const TraitDex = {
  /** Establishment-only: interaction events are not allowed. */
  EstOnly: 'EO',
  /** Do not delegate: this identifier cannot serve as a delegator. */
  DoNotDelegate: 'DND',
} as const;
