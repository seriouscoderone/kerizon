/**
 * Credential proof verification — structural checks on ACDC artifacts
 * and TEL/KEL proof chain linkage.
 */

import type { ProofResult } from './types.js';

export interface CredentialArtifacts {
  acdcSaid: string;
  telEventSaid: string;
  kelSealSaid: string;
  issuerAid: string;
}

export interface ProofChain {
  acdcSaid: string;
  telRegistrySaid: string;
  telSn: number;
  kelAnchorSaid: string;
  issuerAid: string;
}

/**
 * Verify that all required credential artifacts are present.
 * Fails if any field is empty.
 */
export function verifyCredentialArtifacts(artifacts: CredentialArtifacts): ProofResult {
  const entries = Object.entries(artifacts) as [keyof CredentialArtifacts, string][];
  for (const [key, value] of entries) {
    if (!value) {
      return { verified: false, reason: `missing ${key}` };
    }
  }
  return { verified: true };
}

/**
 * Verify a proof chain linking ACDC -> TEL -> KEL.
 * Fails if telSn < 1 (must have at least one TEL event beyond inception).
 */
export function verifyProofChain(chain: ProofChain): ProofResult {
  const { acdcSaid, telRegistrySaid, kelAnchorSaid, issuerAid, telSn } = chain;
  for (const [key, value] of Object.entries({ acdcSaid, telRegistrySaid, kelAnchorSaid, issuerAid })) {
    if (!value) {
      return { verified: false, reason: `missing ${key}` };
    }
  }
  if (telSn < 1) {
    return { verified: false, reason: 'telSn must be >= 1' };
  }
  return { verified: true };
}
