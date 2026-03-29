/**
 * Credential proof types — result types for credential verification
 * and TEL registry state.
 */

export type ProofResult =
  | { verified: true }
  | { verified: false; reason: string };

export interface RegistryState {
  registrySaid: string;
  mode: 'blindable' | 'non-blindable';
  sn: number;
}
