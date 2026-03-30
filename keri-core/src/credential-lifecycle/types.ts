export type RegistryMode = 'blindable' | 'non-blindable';

export interface RegistryRecord {
  readonly registrySaid: string;
  readonly issuerAid: string;
  readonly name: string;
  readonly mode: RegistryMode;
  readonly createdAt: string;
}

export type CredentialState = 'NotIssued' | 'Issued' | 'Revoked';

export interface CredentialStatus {
  readonly state: CredentialState;
  readonly credentialSaid: string;
  readonly registrySaid: string;
  readonly sn: number;
  readonly issuedAt?: string;
  readonly revokedAt?: string;
}

export const TEL_VALID_TRANSITIONS: Record<CredentialState, CredentialState[]> = {
  NotIssued: ['Issued'],
  Issued: ['Revoked'],
  Revoked: [],
};
