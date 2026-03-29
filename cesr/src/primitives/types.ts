/**
 * Shared types for CESR primitives.
 */

/**
 * The two CESR domains:
 * - T-domain: text (URL-safe Base64, no padding)
 * - B-domain: binary (raw bytes)
 */
export interface CesrDomains {
  /** Qualified Base64 representation (T-domain). */
  readonly qb64: string;
  /** Qualified binary representation (B-domain). */
  readonly qb2: Uint8Array;
}
