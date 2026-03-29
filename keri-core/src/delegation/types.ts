export interface DelegatedInceptionConfig {
  delegatorAid: string;
  keys: string[];
  nextDigests: string[];
  signingThreshold?: string;
  nextThreshold?: string;
  witnesses?: string[];
  witnessThreshold?: number;
  configTraits?: string[];
  data?: Record<string, unknown>[];
}

export interface DelegationSeal {
  readonly i: string;  // delegate prefix
  readonly s: string;  // delegate sn (hex)
  readonly d: string;  // delegate event SAID
}
