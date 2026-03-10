import { KeyAlgorithm, SecurityTier } from "./types.js";
import { MtrDex } from "./cesr-helpers.js";

/** Configuration for KeyVault defaults. */
export interface VaultConfig {
  defaultAlgorithm: KeyAlgorithm;
  defaultSecurityTier: SecurityTier;
  defaultDigestCode: string;
  defaultKeyCode: string;
  eraseOnRotation: boolean;
  testMode: boolean;
}

/** Default VaultConfig matching specification §15. */
export const DEFAULT_VAULT_CONFIG: VaultConfig = {
  defaultAlgorithm: KeyAlgorithm.DETERMINISTIC,
  defaultSecurityTier: SecurityTier.LOW,
  defaultDigestCode: MtrDex.Blake3_256,
  defaultKeyCode: MtrDex.Ed25519_Seed,
  eraseOnRotation: true,
  testMode: false,
};
