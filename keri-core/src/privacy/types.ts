/**
 * Privacy domain types for ACDC disclosure classification.
 */

export type PrivacyLevel = 'public' | 'private' | 'metadata';

export type DisclosureType = 'full' | 'compact' | 'partial' | 'selective';

export interface DisclosureRequest {
  readonly acdc: Record<string, unknown>;
  readonly type: DisclosureType;
  /** Field paths for selective disclosure. */
  readonly fields?: string[];
}
