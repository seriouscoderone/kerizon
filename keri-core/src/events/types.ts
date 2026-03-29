export const ICP_FIELDS = ['v', 't', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a'] as const;
export const ROT_FIELDS = ['v', 't', 'd', 'i', 's', 'p', 'kt', 'k', 'nt', 'n', 'bt', 'br', 'ba', 'c', 'a'] as const;
export const IXN_FIELDS = ['v', 't', 'd', 'i', 's', 'p', 'a'] as const;
export const DIP_FIELDS = ['v', 't', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a', 'di'] as const;
export const DRT_FIELDS = ['v', 't', 'd', 'i', 's', 'p', 'kt', 'k', 'nt', 'n', 'bt', 'br', 'ba', 'c', 'a'] as const;

export type EventType = 'icp' | 'rot' | 'ixn' | 'dip' | 'drt';

export interface InceptConfig {
  keys: string[];           // qb64 public keys
  nextDigests: string[];    // qb64 next key digests
  signingThreshold?: string;
  nextThreshold?: string;
  witnesses?: string[];
  witnessThreshold?: number;
  configTraits?: string[];
  data?: Record<string, unknown>[];
  delegator?: string;
}

export interface RotateConfig {
  prefix: string;
  priorDigest: string;
  sn: number;
  keys: string[];
  nextDigests: string[];
  signingThreshold?: string;
  nextThreshold?: string;
  witnessesToAdd?: string[];
  witnessesToRemove?: string[];
  witnessThreshold?: number;
  data?: Record<string, unknown>[];
}

export interface InteractConfig {
  prefix: string;
  priorDigest: string;
  sn: number;
  data?: Record<string, unknown>[];
}
